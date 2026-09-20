package observe

import "github.com/zyvorai/shukra/internal/aggregate"

// hostPID is the slot in which the scheduler counters of every thread that no VM owns are summed. A busy host
// has tens of thousands of them (every thread that has run), and the only use made of them is the "_host"
// row, which is their sum. Keeping one Counters per thread meant allocating and copying tens of megabytes
// every refresh, and the garbage collector took a large share of the daemon's CPU for it. PID 0 is never a
// VM's thread, so aggregate.group counts this slot with the host, as it counted each of them before.
const hostPID = 0

// slot is the Counters for a pid, made on first use.
func slot(by map[uint32]*aggregate.Counters, pid uint32) *aggregate.Counters {
	c := by[pid]
	if c == nil {
		c = &aggregate.Counters{}
		by[pid] = c
	}
	return c
}

// schedSlot is slot for a sched map's entry: a thread of a VM keeps its own, and any other thread is summed
// into the host's. It is only for counters that are sums (time, counts, histogram buckets); a value that is a
// maximum or a last reading would be wrong when folded.
func schedSlot(by map[uint32]*aggregate.Counters, pid uint32) *aggregate.Counters {
	if _, ours := threadRef(pid); !ours {
		pid = hostPID
	}
	return slot(by, pid)
}
