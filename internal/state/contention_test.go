package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

func threeVMs() *State {
	st := New("node-07")
	vm := func(name string, pid int) identity.VM {
		return identity.VM{Name: name, PID: pid, Threads: []int{pid, pid + 1},
			ThreadInfo: []identity.Thread{{TID: pid, Comm: "qemu", Role: "main"}, {TID: pid + 1, Comm: "CPU 0/KVM", Role: "vcpu"}}}
	}
	st.SetVMs([]identity.VM{vm("a", 100), vm("b", 200), vm("c", 300)})
	return st
}

func TestContentionSplitsAVictimsPreemptionIntoOtherVMsItselfAndHostTasks(t *testing.T) {
	st := threeVMs()
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 5_000 * ms, WakeupCount: 1, PreemptNs: 1000 * ms, PreemptCount: 30,
			Preemptors: map[string]uint64{"vm:b": 800 * ms, "vm:a": 100 * ms, "kworker": 60 * ms, "cilium-agent": 40 * ms}},
		201: {OnCPUNs: 9_000 * ms, WakeupCount: 1, Exits: map[uint32]uint64{12: 700}, PreemptNs: 50 * ms, PreemptCount: 3, Preemptors: map[string]uint64{"vm:c": 50 * ms}},
		301: {OnCPUNs: 100 * ms, WakeupCount: 1, Exits: map[uint32]uint64{12: 5}},
	})
	c := st.Contention("", time.Now(), time.Minute)
	if len(c.Pairs) != 2 || c.Pairs[0] != (ContentionPair{Victim: "a", Culprit: "b", PreemptedNs: 800 * ms, Share: 0.8}) ||
		c.Pairs[1].Victim != "b" || c.Pairs[1].Culprit != "c" || c.Pairs[1].Share != 1 {
		t.Fatalf("pairs, most time first, with each one's share of that victim's total: %+v", c.Pairs)
	}
	var a ContentionVictim
	for _, v := range c.Victims {
		if v.VM == "a" {
			a = v
		}
	}
	if a.PreemptedNs != 1000*ms || a.PreemptedCount != 30 || a.ByOtherVMsNs != 800*ms || a.BySelfNs != 100*ms || a.ByHostNs != 100*ms ||
		len(a.HostTasks) != 2 || a.HostTasks[0].Who != "kworker" {
		t.Fatalf("the three parts must add up to what was preempted: %+v", a)
	}
	if len(c.Culprits) != 2 || c.Culprits[0].VM != "b" || c.Culprits[0].TookNs != 800*ms || c.Culprits[0].Victims != 1 ||
		c.Culprits[0].OnCPUNs != 9_000*ms || c.Culprits[0].Exits != 700 {
		t.Fatalf("a culprit is shown with what it was doing: %+v", c.Culprits)
	}
	if c.Victims[0].VM != "a" {
		t.Fatalf("victims are most-preempted first: %+v", c.Victims)
	}
}

func TestAVMThatNothingPreemptedIsAZeroRowAndAnUnmeasuredVMHasNone(t *testing.T) {
	st := threeVMs()
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 1, WakeupCount: 1},
		// b and c have no counters at all: the sched program has not measured them
	})
	c := st.Contention("", time.Now(), time.Minute)
	if len(c.Victims) != 1 || c.Victims[0].VM != "a" || c.Victims[0].PreemptedNs != 0 {
		t.Fatalf("a measured VM with no preemption is a zero row, and an unmeasured one has no row: %+v", c.Victims)
	}
	if c.Pairs == nil || c.Culprits == nil || c.Victims[0].HostTasks == nil {
		t.Fatal("every list must be [] and not null")
	}
	if empty := New("n").Contention("", time.Now(), time.Minute); empty.Pairs == nil || empty.Victims == nil || empty.Culprits == nil {
		t.Fatalf("%+v", empty)
	}
}

func TestContentionForOneVMIsThatVMAsTheVictimAndOnlyWhatItSuffered(t *testing.T) {
	st := threeVMs()
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 100 * ms, Preemptors: map[string]uint64{"vm:b": 100 * ms}},
		201: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 300 * ms, Preemptors: map[string]uint64{"vm:c": 300 * ms}},
		301: {OnCPUNs: 1, WakeupCount: 1},
	})
	c := st.Contention("a", time.Now(), time.Minute)
	if len(c.Victims) != 1 || c.Victims[0].VM != "a" || len(c.Pairs) != 1 || c.Pairs[0].Culprit != "b" {
		t.Fatalf("%+v", c)
	}
	if len(c.Culprits) != 1 || c.Culprits[0].TookNs != 100*ms {
		t.Fatalf("what c took from b is not a's business: %+v", c.Culprits)
	}
}

func TestContentionOverAWindowIsTheWindowsPreemptionNotTheLifetimes(t *testing.T) {
	c := newClocked(t) // one VM, "db", with vCPU thread 101
	c.SetVMs([]identity.VM{
		{Name: "db", PID: 100, Threads: []int{100, 101}, ThreadInfo: []identity.Thread{{TID: 100, Comm: "qemu", Role: "main"}, {TID: 101, Comm: "CPU 0/KVM", Role: "vcpu"}}},
		{Name: "web", PID: 200, Threads: []int{200, 201}, ThreadInfo: []identity.Thread{{TID: 200, Comm: "qemu", Role: "main"}, {TID: 201, Comm: "CPU 0/KVM", Role: "vcpu"}}},
	})
	old := map[uint32]aggregate.Counters{
		101: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 40_000 * ms, Preemptors: map[string]uint64{"vm:web": 40_000 * ms}},
		201: {OnCPUNs: 1, WakeupCount: 1},
	}
	now := map[uint32]aggregate.Counters{
		101: {OnCPUNs: 2, WakeupCount: 2, PreemptNs: 40_500 * ms, Preemptors: map[string]uint64{"vm:web": 40_100 * ms, "kworker": 400 * ms}},
		201: {OnCPUNs: 2, WakeupCount: 2},
	}
	c.at(0, old)
	c.at(30*time.Second, now)
	c.at(60*time.Second, now)
	got := c.Contention("db", t0.Add(60*time.Second), time.Minute)
	if got.Window == "lifetime" || len(got.Victims) != 1 {
		t.Fatalf("%+v", got)
	}
	v := got.Victims[0]
	if v.PreemptedNs != 500*ms || v.ByOtherVMsNs != 100*ms || v.ByHostNs != 400*ms {
		t.Fatalf("only what happened in the window: %+v", v)
	}
	if life := c.Contention("db", t0.Add(60*time.Second), 0); life.Window != "lifetime" || life.Victims[0].PreemptedNs != 40_500*ms {
		t.Fatalf("a zero window is the lifetime: %+v", life)
	}
}

func preemptedBy(vm string, who ...aggregate.Preemptor) aggregate.SchedRow {
	var total uint64
	for _, w := range who {
		total += w.Ns
	}
	return aggregate.SchedRow{VM: vm, Measured: true, PreemptedNs: total, PreemptedCount: 20, Preemptors: who}
}

func TestANoisyNeighbourIsNamedWhenOneOtherVMTookMostOfTheTime(t *testing.T) {
	threads := []aggregate.ThreadRow{{TID: 11, Role: "vcpu", OnCPUNs: 800 * ms}}
	sched := []aggregate.SchedRow{preemptedBy("db", aggregate.Preemptor{Who: "vm:web", Ns: 600 * ms}, aggregate.Preemptor{Who: "kworker", Ns: 100 * ms})}
	fs := diagnose(true, quiet, sched, threads, nil, nil, nil, nil)
	f := find(fs, "noisy_neighbour")
	if f == nil || !strings.Contains(f.Summary, "web") || !strings.Contains(f.Evidence[0], "trace contention") || !strings.Contains(f.Evidence[0], "86%") {
		t.Fatalf("%+v", fs)
	}
	if find(fs, "cpu_preempted") == nil {
		t.Fatal("the general finding stays: the neighbour is added to it")
	}
	if pre := find(fs, "cpu_preempted"); pre.Confidence != f.Confidence {
		t.Fatalf("both findings rest on the same numbers: %s and %s", pre.Confidence, f.Confidence)
	}
}

func TestNoNeighbourIsNamedForHostTasksItsOwnThreadsOrASmallShare(t *testing.T) {
	threads := []aggregate.ThreadRow{{TID: 11, Role: "vcpu", OnCPUNs: 800 * ms}}
	for name, sched := range map[string][]aggregate.SchedRow{
		"host task first":   {preemptedBy("db", aggregate.Preemptor{Who: "kworker", Ns: 500 * ms}, aggregate.Preemptor{Who: "vm:web", Ns: 200 * ms})},
		"its own threads":   {preemptedBy("db", aggregate.Preemptor{Who: "vm:db", Ns: 600 * ms}, aggregate.Preemptor{Who: "kworker", Ns: 100 * ms})},
		"under half":        {preemptedBy("db", aggregate.Preemptor{Who: "vm:web", Ns: 300 * ms}, aggregate.Preemptor{Who: "vm:api", Ns: 290 * ms}, aggregate.Preemptor{Who: "kworker", Ns: 110 * ms})},
		"too little in all": {preemptedBy("db", aggregate.Preemptor{Who: "vm:web", Ns: 100 * ms})},
	} {
		fs := diagnose(true, quiet, sched, threads, nil, nil, nil, nil)
		if find(fs, "noisy_neighbour") != nil {
			t.Errorf("%s: named a neighbour: %+v", name, fs)
		}
	}
}

func TestACulpritThatHurtsTwoVMsIsOneRowWithBothTotalledAndAtMostFiveHostTasksAreListed(t *testing.T) {
	st := threeVMs()
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 400 * ms, Preemptors: map[string]uint64{
			"vm:b": 100 * ms, "t1": 70 * ms, "t2": 60 * ms, "t3": 50 * ms, "t4": 40 * ms, "t5": 30 * ms, "t6": 20 * ms, "t7": 10 * ms, "t8": 20 * ms}},
		301: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 200 * ms, Preemptors: map[string]uint64{"vm:b": 200 * ms}},
		201: {OnCPUNs: 7 * ms, WakeupCount: 1},
	})
	c := st.Contention("", time.Now(), time.Minute)
	if len(c.Culprits) != 1 || c.Culprits[0].VM != "b" || c.Culprits[0].TookNs != 300*ms || c.Culprits[0].Victims != 2 {
		t.Fatalf("%+v", c.Culprits)
	}
	for _, v := range c.Victims {
		if v.VM == "a" && (len(v.HostTasks) != 5 || v.HostTasks[0].Who != "t1" || v.HostTasks[4].Who != "t5") {
			t.Fatalf("the five that took the most: %+v", v.HostTasks)
		}
	}
}
