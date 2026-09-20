//go:build shukrabpf && linux

package observe

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zyvorai/shukra/internal/event"
)

// TestKernelIntegrationVMMTripwires loads the real vmm program and checks what it reports against calls this test
// makes itself. The test process stands in for a QEMU process: it is put on the watched list, so what it opens, and
// what the programs it starts open, are what a VMM and its children would do. Nothing else on the machine is
// watched, so nothing else can move the numbers, and it is safe on a production host: its maps are its own.
//
//	sudo SHUKRA_BPF_TEST=1 go test -tags shukrabpf -run TestKernelIntegrationVMM -v ./internal/observe
func TestKernelIntegrationVMMTripwires(t *testing.T) {
	if os.Getenv("SHUKRA_BPF_TEST") != "1" {
		t.Skip("set SHUKRA_BPF_TEST=1 to load BPF programs into the kernel")
	}
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	for _, p := range Programs() {
		if p.Name == "vmm" && !strings.HasPrefix(p.Status, "attached") {
			t.Fatalf("vmm is not attached: %s %s", p.Status, p.Detail)
		}
	}

	var mu sync.Mutex
	var events []event.Event
	StartVMM(func(e event.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	me := uint32(os.Getpid())
	SetWatched([]uint32{me})
	t.Cleanup(func() { SetWatched(nil) })

	// found waits for an event that satisfies pred, since the ring is read by another goroutine.
	found := func(pred func(event.Event) bool) (event.Event, bool) {
		for i := 0; i < 100; i++ {
			mu.Lock()
			for _, e := range events {
				if pred(e) {
					mu.Unlock()
					return e, true
				}
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
		return event.Event{}, false
	}
	openOf := func(path string) func(event.Event) bool {
		return func(e event.Event) bool { return e.Kind == event.KindVMMOpen && e.Path == path }
	}
	callOf := func(name string) func(event.Event) bool {
		return func(e event.Event) bool { return e.Kind == event.KindVMMCall && e.Syscall == name && e.TGID == me }
	}
	unique := func(what string) string {
		return fmt.Sprintf("/nonexistent-shukra-%d-%s-%d", me, what, time.Now().UnixNano())
	}
	quiet := func() { time.Sleep(1100 * time.Millisecond) } // a fresh second for the rate limit

	t.Run("a file the watched process opens is reported with its path, and as a read", func(t *testing.T) {
		p := unique("own")
		_, _ = os.Open(p)
		e, ok := found(openOf(p))
		if !ok {
			t.Fatal("no event")
		}
		if e.Syscall != "openat" || e.PID != me || e.TGID != me || e.Write || e.Comm == "" {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("an open that asks to write says so", func(t *testing.T) {
		p := unique("write")
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600)
		if err == nil {
			f.Close()
			os.Remove(p)
		}
		if e, ok := found(openOf(p)); !ok || !e.Write {
			t.Fatalf("%+v %v", e, ok)
		}
	})

	t.Run("a program the watched process starts is seen, with its own name, and so are its children to three deep", func(t *testing.T) {
		child := unique("child")
		_ = exec.Command("cat", child).Run()
		e, ok := found(openOf(child))
		if !ok || e.Comm != "cat" || e.PID == me || e.TGID != me {
			t.Fatalf("a child: %+v %v", e, ok)
		}
		two := unique("two")
		_ = exec.Command("sh", "-c", "cat "+two+"; true").Run()
		if e, ok := found(openOf(two)); !ok || e.Comm != "cat" || e.TGID != me {
			t.Fatalf("a grandchild: %+v %v", e, ok)
		}
		three := unique("three")
		_ = exec.Command("sh", "-c", "sh -c 'cat "+three+"; true'; true").Run()
		if e, ok := found(openOf(three)); !ok || e.Comm != "cat" || e.TGID != me {
			t.Fatalf("a great-grandchild: %+v %v", e, ok)
		}
	})

	t.Run("a process four levels down is not the VMM's and is not seen", func(t *testing.T) {
		four := unique("four")
		_ = exec.Command("sh", "-c", `sh -c "sh -c 'cat `+four+`; true'; true"; true`).Run()
		time.Sleep(500 * time.Millisecond) // long enough for the ring reader, which has proved itself above
		if _, ok := found(openOf(four)); ok {
			t.Fatal("it was reported: the walk is longer than it says")
		}
	})

	t.Run("nothing is reported for a process that is not watched", func(t *testing.T) {
		SetWatched(nil)
		p := unique("unwatched")
		_, _ = os.Open(p)
		_ = exec.Command("cat", p).Run()
		time.Sleep(500 * time.Millisecond)
		if _, ok := found(openOf(p)); ok {
			t.Fatal("an unwatched process was reported")
		}
		SetWatched([]uint32{me})
		p2 := unique("watched-again")
		_, _ = os.Open(p2)
		if _, ok := found(openOf(p2)); !ok {
			t.Fatal("putting it back on the list did not bring the reports back")
		}
	})

	t.Run("a relative path is reported as given, and one relative to a descriptor says which", func(t *testing.T) {
		rel := fmt.Sprintf("relative-shukra-%d", time.Now().UnixNano())
		_, _ = os.Open(rel)
		if e, ok := found(openOf(rel)); !ok || e.Detail != "" {
			t.Fatalf("%+v %v", e, ok)
		}
		dir, err := os.Open("/tmp")
		if err != nil {
			t.Skip("no /tmp")
		}
		defer dir.Close()
		viaFD := fmt.Sprintf("viafd-shukra-%d", time.Now().UnixNano())
		_, _ = unix.Openat(int(dir.Fd()), viaFD, unix.O_RDONLY, 0)
		if e, ok := found(openOf(viaFD)); !ok || e.Detail != fmt.Sprintf("relative to fd %d", dir.Fd()) {
			t.Fatalf("%+v %v", e, ok)
		}
	})

	t.Run("a path longer than the buffer is cut to it", func(t *testing.T) {
		long := "/nonexistent-" + strings.Repeat("a", 400)
		_, _ = os.Open(long)
		e, ok := found(func(e event.Event) bool {
			return e.Kind == event.KindVMMOpen && strings.HasPrefix(e.Path, "/nonexistent-aaaa") && len(e.Path) > 200
		})
		if !ok || len(e.Path) != vmmPathMax-1 {
			t.Fatalf("%d %v", len(e.Path), ok)
		}
	})

	t.Run("each call a VMM has no business making is reported by name, with its arguments", func(t *testing.T) {
		unix.Syscall6(unix.SYS_PTRACE, 2, 1, 0, 0, 0, 0) // PEEKDATA on init: refused, and reported first
		if e, ok := found(callOf("ptrace")); !ok || e.Detail != "request 2 (PEEKDATA) on pid 1" {
			t.Fatalf("ptrace: %+v %v", e, ok)
		}
		_ = unix.Mount("none", "/nonexistent-shukra-mount", "tmpfs", 0, "")
		if e, ok := found(callOf("mount")); !ok || e.Detail != "flags 0x0" {
			t.Fatalf("mount: %+v %v", e, ok)
		}
		_ = unix.Unshare(0)
		if e, ok := found(callOf("unshare")); !ok || e.Detail != "no namespace flag" {
			t.Fatalf("unshare: %+v %v", e, ok)
		}
		unix.Syscall(unix.SYS_SETNS, ^uintptr(0), 0, 0)
		if e, ok := found(callOf("setns")); !ok || e.Detail != "into the namespace of fd -1, type 0x0" {
			t.Fatalf("setns: %+v %v", e, ok)
		}
		unix.Syscall6(unix.SYS_PROCESS_VM_READV, 1, 0, 0, 0, 0, 0)
		if e, ok := found(callOf("process_vm_readv")); !ok || e.Detail != "reads the memory of pid 1" {
			t.Fatalf("process_vm_readv: %+v %v", e, ok)
		}
		unix.Syscall6(unix.SYS_PROCESS_VM_WRITEV, 1, 0, 0, 0, 0, 0)
		if e, ok := found(callOf("process_vm_writev")); !ok || e.Detail != "writes the memory of pid 1" {
			t.Fatalf("process_vm_writev: %+v %v", e, ok)
		}
	})

	t.Run("a VMM that makes more calls than the limit has the excess counted and reported once the second is over", func(t *testing.T) {
		quiet()
		tag := fmt.Sprintf("/nonexistent-shukra-flood-%d-", me)
		const n = 1200
		for i := 0; i < n; i++ {
			_, _ = os.Open(fmt.Sprintf("%s%d", tag, i))
		}
		quiet()
		_, _ = os.Open(unique("after")) // the next call after the second reports the flood
		f, ok := found(func(e event.Event) bool { return e.Kind == event.KindVMMCall && e.Syscall == "flood" && e.TGID == me })
		if !ok {
			t.Fatal("no flood report")
		}
		mu.Lock()
		reported := 0
		for _, e := range events {
			if e.Kind == event.KindVMMOpen && strings.HasPrefix(e.Path, tag) {
				reported++
			}
		}
		mu.Unlock()
		if reported > 320 || reported < 250 {
			t.Fatalf("%d of %d reported: the limit is 300 a second", reported, n)
		}
		if f.Count < uint64(n-reported-100) || f.Count > uint64(n-reported+50) {
			t.Fatalf("the flood says %d were not reported, and %d were reported of %d", f.Count, reported, n)
		}
	})

	t.Run("the process id of a call is the process, not the thread, and the VMM is the root", func(t *testing.T) {
		var tid int
		done := make(chan struct{})
		p := unique("thread")
		go func() {
			tid = syscall.Gettid()
			_, _ = os.Open(p)
			close(done)
		}()
		<-done
		if e, ok := found(openOf(p)); !ok || e.PID != me || e.TGID != me || uint32(tid) == me {
			t.Fatalf("%+v %v (thread %d)", e, ok, tid)
		}
	})
}
