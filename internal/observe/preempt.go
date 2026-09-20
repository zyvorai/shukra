package observe

import (
	"strings"
	"sync"

	"github.com/zyvorai/shukra/internal/aggregate"
)

// ThreadRef says which VM a host thread belongs to and what it does (vcpu, iothread, ...), from the
// daemon's /proc scan. The sched program counts preemption for every watched thread; only a vCPU thread's
// wait is reported, and a preemptor that is another QEMU thread is named by its VM.
type ThreadRef struct {
	VM   string
	Role string
}

var threads struct {
	mu sync.RWMutex
	m  map[uint32]ThreadRef
}

// SetThreads replaces the thread table. The daemon calls it on every scan.
func SetThreads(m map[uint32]ThreadRef) {
	threads.mu.Lock()
	threads.m = m
	threads.mu.Unlock()
}

func threadRef(tid uint32) (ThreadRef, bool) {
	threads.mu.RLock()
	defer threads.mu.RUnlock()
	r, ok := threads.m[tid]
	return r, ok
}

// VMPrefix marks a preemptor that is a thread of a VM: "vm:web-01".
const VMPrefix = aggregate.VMLabel

// preemptorLabel names who took a vCPU's CPU. A thread of a QEMU process is the VM's (which may be the
// victim's own VM: its iothread or another vCPU), and anything else is its command name with the per-CPU or
// per-instance suffix removed, so "kworker/3:1" and "kworker/u16:2" are one preemptor, "kworker", and
// "ksoftirqd/3" is "ksoftirqd". The comm is what the kernel reported when the thread was preempted.
func preemptorLabel(byTid uint32, comm string, owners func(uint32) (ThreadRef, bool)) string {
	if r, ok := owners(byTid); ok && r.VM != "" {
		return VMPrefix + r.VM
	}
	comm = strings.TrimSpace(comm)
	if i := strings.IndexByte(comm, '/'); i > 0 {
		comm = comm[:i]
	}
	if comm == "" {
		return "unknown"
	}
	return comm
}

// commString reads a kernel comm: NUL-terminated inside a fixed 16-byte array.
func commString(b [16]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
