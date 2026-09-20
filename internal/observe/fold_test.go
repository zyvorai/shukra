package observe

import (
	"reflect"
	"testing"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/hist"
	"github.com/zyvorai/shukra/internal/identity"
)

type reading struct {
	pid                       uint32
	onCPU, wakeDelay, wakeups uint64
	bucket                    uint32
	count                     uint64
}

// world is two VMs whose threads are known to the daemon and a crowd of other threads that are not.
func world(t *testing.T) ([]identity.VM, []reading) {
	t.Helper()
	t.Cleanup(func() { SetThreads(nil) })
	vms := []identity.VM{
		{Name: "web", PID: 100, Threads: []int{100, 101, 102}},
		{Name: "db", PID: 200, Threads: []int{200, 201}},
	}
	refs := map[uint32]ThreadRef{}
	for _, vm := range vms {
		for _, t := range vm.Threads {
			refs[uint32(t)] = ThreadRef{VM: vm.Name, Role: "vcpu"}
		}
	}
	SetThreads(refs)
	var rs []reading
	pids := []uint32{100, 101, 102, 200, 201}
	for i := uint32(0); i < 300; i++ {
		pids = append(pids, 5000+i) // threads no VM owns
	}
	for i, pid := range pids {
		rs = append(rs, reading{pid: pid, onCPU: uint64(1000 + i*7), wakeDelay: uint64(50 + i), wakeups: uint64(3 + i%5), bucket: uint32(i % hist.Buckets), count: uint64(1 + i%11)})
	}
	return vms, rs
}

// apply adds a reading the way readSched and readHist2 do, through the given slot function.
func apply(by map[uint32]*aggregate.Counters, r reading, slotFor func(map[uint32]*aggregate.Counters, uint32) *aggregate.Counters) {
	c := slotFor(by, r.pid)
	c.OnCPUNs += r.onCPU
	c.WakeupDelayNs += r.wakeDelay
	c.WakeupCount += r.wakeups
	h := &c.SchedHist
	if *h == nil {
		*h = make([]uint64, hist.Buckets)
	}
	(*h)[r.bucket] += r.count
}

func values(by map[uint32]*aggregate.Counters) map[uint32]aggregate.Counters {
	out := map[uint32]aggregate.Counters{}
	for pid, c := range by {
		out[pid] = *c
	}
	return out
}

// Folding the threads that no VM owns must change nothing the API says: the rows come out the same as when
// every thread had a Counters of its own.
func TestFoldingTheHostsThreadsGivesTheRowsThatOneCountersPerThreadGave(t *testing.T) {
	vms, rs := world(t)
	each := map[uint32]*aggregate.Counters{}
	folded := map[uint32]*aggregate.Counters{}
	for _, r := range rs {
		apply(each, r, slot)
		apply(folded, r, schedSlot)
	}
	want := aggregate.Sched(vms, values(each), "")
	got := aggregate.Sched(vms, values(folded), "")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows differ:\n got %+v\nwant %+v", got, want)
	}
	host := false
	for _, row := range got {
		if row.VM == aggregate.Host {
			host = row.OnCPUNs > 0 && row.WakeupCount > 0 && row.WakeupDelayP50Ns > 0
		}
	}
	if !host {
		t.Fatalf("the host row is still there and still measured: %+v", got)
	}
	// The threads of a VM are kept apart: their own rows are per thread.
	if !reflect.DeepEqual(aggregate.SchedThreads(vms, values(folded), ""), aggregate.SchedThreads(vms, values(each), "")) {
		t.Fatal("per-thread rows changed")
	}
}

func TestFoldingMakesOneSlotForAllThreadsNoVMOwns(t *testing.T) {
	_, rs := world(t)
	by := map[uint32]*aggregate.Counters{}
	for _, r := range rs {
		apply(by, r, schedSlot)
	}
	// five owned threads, and one slot that holds all 300 others
	if len(by) != 6 {
		t.Fatalf("%d slots", len(by))
	}
	if by[hostPID] == nil {
		t.Fatal("no host slot")
	}
	for _, owned := range []uint32{100, 101, 102, 200, 201} {
		if by[owned] == nil {
			t.Fatalf("thread %d lost its own slot", owned)
		}
	}
}

func TestAThreadTheDaemonHasNotSeenYetIsTheHostsUntilItIs(t *testing.T) {
	t.Cleanup(func() { SetThreads(nil) })
	SetThreads(map[uint32]ThreadRef{})
	by := map[uint32]*aggregate.Counters{}
	schedSlot(by, 777).OnCPUNs = 5
	if len(by) != 1 || by[hostPID] == nil || by[hostPID].OnCPUNs != 5 {
		t.Fatalf("%v", by)
	}
	SetThreads(map[uint32]ThreadRef{777: {VM: "web", Role: "vcpu"}})
	schedSlot(by, 777).OnCPUNs += 3
	if by[777] == nil || by[777].OnCPUNs != 3 {
		t.Fatalf("%v", by)
	}
}
