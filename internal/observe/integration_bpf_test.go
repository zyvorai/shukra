//go:build shukrabpf && linux

package observe

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

// TestKernelIntegration loads the real eBPF programs into the running kernel and
// checks what they count against load this test generates itself. It is the check
// that a new kernel's verifier still accepts the programs and that the counters
// mean what the docs say.
//
// BPF counters are keyed by thread id, so the test locks its goroutine to one OS
// thread and reads that thread's row. Other processes on the machine cannot move
// the numbers, which is what lets every assertion be exact.
//
// It needs root and a kernel with BTF, so it only runs when asked:
//
//	sudo SHUKRA_BPF_TEST=1 go test -tags shukrabpf -run TestKernelIntegration -v ./internal/observe
//
// dualStackConnect connects an AF_INET6 socket with IPV6_V6ONLY off to a v4-mapped
// address. The port is closed, so it is refused at once, and the connect attempt
// is what the kernel program counts.
func dualStackConnect(t *testing.T, addr [16]byte, port int) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Connect(fd, &syscall.SockaddrInet6{Port: port, Addr: addr}) // refused
}

func TestKernelIntegration(t *testing.T) {
	if os.Getenv("SHUKRA_BPF_TEST") != "1" {
		t.Skip("set SHUKRA_BPF_TEST=1 to load BPF programs into the kernel")
	}
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}

	programs := map[string]string{}
	for _, p := range Programs() {
		programs[p.Name] = p.Status + ": " + p.Detail
	}
	// kvm is not required: its tracepoints depend on the kvm module and the CPU.
	for _, name := range []string{"sched", "block", "net"} {
		if s := programs[name]; len(s) < 8 || s[:8] != "attached" {
			t.Fatalf("%s is not attached: %s", name, s)
		}
	}

	var mu sync.Mutex
	var events []event.Event
	var netTid uint32 // the thread the connect subtest ran on
	Start(func(e event.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	SetWatched([]uint32{uint32(os.Getpid())})

	// t.Run starts every subtest on a new goroutine, so the thread has to be
	// pinned inside the subtest that does the work, and that same thread's row is
	// the one to read.
	pin := func(t *testing.T) uint32 {
		runtime.LockOSThread()
		t.Cleanup(runtime.UnlockOSThread)
		return uint32(syscall.Gettid())
	}
	type counts struct {
		connects, wOps, wBytes, rOps, rBytes, wMax uint64
		wHist, rHist                               uint64
	}
	rowFor := func(tid uint32) (c counts) {
		s, ok := Sample()[tid]
		if !ok {
			return
		}
		c.connects, c.wOps, c.wBytes, c.rOps, c.rBytes, c.wMax = s.Connects, s.BlockWriteOps, s.BlockWriteBytes, s.BlockReadOps, s.BlockReadBytes, s.BlockWriteMax
		for _, n := range s.BlockWrite {
			c.wHist += n
		}
		for _, n := range s.BlockRead {
			c.rHist += n
		}
		return
	}

	t.Run("connects are counted exactly, once each, for IPv4 IPv6 and dual-stack", func(t *testing.T) {
		v6 := true
		if ln, err := net.Listen("tcp6", "[::1]:0"); err != nil {
			v6 = false
			t.Log("no IPv6 loopback here; skipping the IPv6 and dual-stack cases")
		} else {
			ln.Close()
		}
		tid := pin(t)
		netTid = tid
		row := func() counts { return rowFor(tid) }
		before := row().connects
		dial := func(network, addr string, n int) {
			for i := 0; i < n; i++ {
				c, err := net.DialTimeout(network, addr, 500*time.Millisecond)
				if err == nil {
					c.Close()
				}
			}
		}
		// Port 9 (discard) is closed, so each attempt is refused at once, and the
		// kprobe sees the attempt whether or not it succeeds.
		dial("tcp4", "127.0.0.1:9", 5)
		want := uint64(5)
		if v6 {
			dial("tcp6", "[::1]:9", 3)
			// A v4-mapped address on a dual-stack AF_INET6 socket goes through
			// tcp_v6_connect and on to tcp_v4_connect. It must count once, not twice.
			// Go's own tcp6 dialer sets IPV6_V6ONLY, which makes the kernel refuse a
			// v4-mapped address before any connection is attempted, so this uses a
			// raw socket with V6ONLY off.
			for i := 0; i < 4; i++ {
				dualStackConnect(t, [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1}, 9)
			}
			want += 3 + 4
		}
		if got := row().connects - before; got != want {
			t.Fatalf("kernel counted %d connects, want %d", got, want)
		}
	})

	t.Run("block bytes match what was written and read", func(t *testing.T) {
		const chunk, chunks = 1 << 20, 32
		tid := pin(t)
		row := func() counts { return rowFor(tid) }
		dir := os.TempDir()
		f, err := os.OpenFile(dir+"/shukra-it.dat", os.O_CREATE|os.O_RDWR|os.O_TRUNC|syscall.O_DIRECT, 0o600)
		if err != nil {
			f, err = os.OpenFile("/var/tmp/shukra-it.dat", os.O_CREATE|os.O_RDWR|os.O_TRUNC|syscall.O_DIRECT, 0o600)
		}
		if err != nil {
			t.Skipf("no filesystem here that allows O_DIRECT: %v", err)
		}
		defer os.Remove(f.Name())
		defer f.Close()
		// O_DIRECT needs an aligned buffer. An anonymous mapping is page aligned.
		buf, err := syscall.Mmap(-1, 0, chunk, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Munmap(buf)
		for i := range buf {
			buf[i] = byte(i)
		}
		before := row()
		for i := 0; i < chunks; i++ {
			if _, err := f.WriteAt(buf, int64(i)*chunk); err != nil {
				t.Skipf("direct write failed: %v", err)
			}
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < chunks; i++ {
			if _, err := f.ReadAt(buf, int64(i)*chunk); err != nil {
				t.Skipf("direct read failed: %v", err)
			}
		}
		time.Sleep(200 * time.Millisecond) // completions are counted in interrupt context
		after := row()
		w, r := after.wBytes-before.wBytes, after.rBytes-before.rBytes
		const total = chunk * chunks
		// Bytes are attributed to the task that dispatched the request. That is
		// nearly always the submitting thread, but the block layer sometimes
		// dispatches from a kernel worker, and those requests belong to that
		// worker's row instead (about 3% of reads in a run on a 6.8 kernel). So
		// require most of the bytes, and no more than the file plus a little
		// filesystem metadata. Exact accounting is not what this signal promises.
		if w < total*85/100 || w > total+total/4 {
			t.Fatalf("write bytes %d, wrote %d", w, total)
		}
		if r < total*85/100 || r > total+total/4 {
			t.Fatalf("read bytes %d, read %d", r, total)
		}
		if after.wOps == before.wOps || after.rOps == before.rOps {
			t.Fatal("no requests counted")
		}
		if after.wMax == 0 {
			t.Fatal("the slowest write was not recorded")
		}
		// Every completed request is in the latency histogram exactly once.
		if after.wHist-before.wHist != after.wOps-before.wOps || after.rHist-before.rHist != after.rOps-before.rOps {
			t.Fatalf("histogram counts do not match request counts: w %d/%d r %d/%d",
				after.wHist-before.wHist, after.wOps-before.wOps, after.rHist-before.rHist, after.rOps-before.rOps)
		}
	})

	t.Run("exec events are only for children of a watched process, and carry the parent", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		mark := len(events)
		mu.Unlock()
		// Direct children of this process (watched): three /bin/true.
		for i := 0; i < 3; i++ {
			_ = exec.Command("/bin/true").Run()
		}
		// A shell that runs /bin/true twice. The shell is our child. Its children
		// are grandchildren, so the filter must drop them.
		_ = exec.Command("/bin/sh", "-c", "/bin/true; /bin/true; echo done").Run()
		time.Sleep(500 * time.Millisecond)

		mu.Lock()
		got := append([]event.Event(nil), events[mark:]...)
		mu.Unlock()
		self := uint32(os.Getpid())
		var trueChildren, shells, grandchildren int
		for _, e := range got {
			if e.Kind != event.KindExec {
				continue
			}
			switch {
			case e.Comm == "true" && e.PPID == self:
				trueChildren++
			case (e.Comm == "sh" || e.Comm == "dash") && e.PPID == self:
				shells++
			case e.Comm == "true":
				grandchildren++
			}
		}
		if trueChildren != 3 || shells != 1 {
			t.Fatalf("children of the watched process: %d true, %d sh (want 3 and 1); events %+v", trueChildren, shells, got)
		}
		if grandchildren != 0 {
			t.Fatalf("%d exec events for grandchildren leaked through the filter", grandchildren)
		}
	})

	t.Run("connect events carry the destination for both families", func(t *testing.T) {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		seen := map[string]int{}
		for _, e := range events {
			if e.Kind == event.KindTCPConnect && e.PID == netTid && e.DPort == 9 {
				seen[e.Dst]++
			}
		}
		if seen["127.0.0.1"] == 0 {
			t.Fatalf("no IPv4 connect events for this thread: %v", seen)
		}
		if _, ok := seen["::1"]; !ok {
			if ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
				ln.Close()
				t.Fatalf("IPv6 is available but no ::1 connect event arrived: %v", seen)
			}
		}
	})
}
