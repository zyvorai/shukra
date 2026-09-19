package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

var t0 = time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

// clocked is a state with one VM, a controllable clock, and helpers to advance it.
type clocked struct {
	*State
	now time.Time
}

func newClocked(t *testing.T) *clocked {
	t.Helper()
	c := &clocked{State: New("node-07"), now: t0}
	c.clock = func() time.Time { return c.now }
	c.SetVMs([]identity.VM{{
		Name: "db", PID: 100, Threads: []int{100, 101},
		ThreadInfo: []identity.Thread{{TID: 100, Comm: "qemu", Role: "main"}, {TID: 101, Comm: "CPU 0/KVM", Role: "vcpu"}},
	}})
	return c
}

// at sets the counters as they are at t0+d and takes the snapshot the daemon would.
func (c *clocked) at(d time.Duration, by map[uint32]aggregate.Counters) {
	c.now = t0.Add(d)
	c.SetCounters(by)
}

func bucket(pairs map[int]uint64) []uint64 {
	h := make([]uint64, 64)
	for i, n := range pairs {
		h[i] = n
	}
	return h
}

func causeOf(ex Explain, cause string) *Finding { return find(ex.Findings, cause) }

// slowThenFast: a disk that was very slow long ago (bucket 27 is about 268 ms) and has
// been fast (bucket 15, about 65 us) ever since. The old slow requests are 4.8% of
// everything, which is enough to hold a lifetime p99 in the slow bucket for good.
func slowThenFast() (early, late map[uint32]aggregate.Counters) {
	early = map[uint32]aggregate.Counters{
		101: {BlockIssues: 5000, BlockWriteOps: 5000, BlockWrite: bucket(map[int]uint64{27: 5000}), OnCPUNs: 1},
	}
	late = map[uint32]aggregate.Counters{
		101: {BlockIssues: 105000, BlockWriteOps: 105000, BlockWrite: bucket(map[int]uint64{27: 5000, 15: 100000}), OnCPUNs: 2},
	}
	return
}

func TestALongGoneSlowDiskIsNotBlamedNow(t *testing.T) {
	c := newClocked(t)
	early, late := slowThenFast()
	c.at(0, early)
	c.at(30*time.Minute, late) // recorded, but 30 minutes on
	c.at(30*time.Minute+30*time.Second, late)
	c.at(30*time.Minute+60*time.Second, late)

	now := t0.Add(30*time.Minute + 60*time.Second)
	recent := c.ExplainOver("db", now, time.Minute)
	if causeOf(recent, "storage_latency") != nil {
		t.Fatalf("the slow disk was 30 minutes ago and is fast now, but: %+v", recent.Findings)
	}
	if recent.Window == "lifetime" || !strings.HasPrefix(recent.Basis, "Over the last") {
		t.Fatalf("window %q basis %q", recent.Window, recent.Basis)
	}
	// Lifetime still carries the old slow requests, which is exactly the misreading.
	life := c.ExplainOver("db", now, 0)
	if f := causeOf(life, "storage_latency"); f == nil {
		t.Fatalf("lifetime should still show the old slow requests: %+v", life.Findings)
	}
	if life.Window != "lifetime" || life.Basis != Basis {
		t.Fatalf("window %q basis %q", life.Window, life.Basis)
	}
}

func TestASlowDiskInsideTheWindowIsFound(t *testing.T) {
	c := newClocked(t)
	fast := map[uint32]aggregate.Counters{101: {BlockIssues: 1000, BlockWriteOps: 1000, BlockWrite: bucket(map[int]uint64{15: 1000}), OnCPUNs: 1}}
	slow := map[uint32]aggregate.Counters{101: {BlockIssues: 1300, BlockWriteOps: 1300, BlockWrite: bucket(map[int]uint64{15: 1000, 27: 300}), OnCPUNs: 2}}
	c.at(0, fast)
	c.at(30*time.Second, slow)
	c.at(60*time.Second, slow)
	ex := c.ExplainOver("db", t0.Add(60*time.Second), time.Minute)
	f := causeOf(ex, "storage_latency")
	if f == nil || f.Confidence != "high" || !strings.Contains(f.Evidence[0], "300 requests") {
		t.Fatalf("%+v", ex.Findings)
	}
	// The count in the evidence is the window's 300, not the lifetime 1300.
	if strings.Contains(f.Evidence[0], "1300") {
		t.Fatalf("lifetime request count leaked into a windowed finding: %q", f.Evidence[0])
	}
}

func TestTooLittleHistoryFallsBackToLifetimeAndSaysSo(t *testing.T) {
	c := newClocked(t)
	early, _ := slowThenFast()
	c.at(0, early)
	c.at(10*time.Second, early) // 10s of history is less than the 20s minimum
	ex := c.ExplainOver("db", t0.Add(10*time.Second), time.Minute)
	if ex.Window != "lifetime" || ex.Basis != Basis {
		t.Fatalf("window %q basis %q", ex.Window, ex.Basis)
	}
	if causeOf(ex, "storage_latency") == nil {
		t.Fatal("with no window to look at, the lifetime data is what there is")
	}
	// And with no history at all.
	if ex := New("x").Explain("nope", t0); ex.Window != "lifetime" {
		t.Fatalf("%q", ex.Window)
	}
}

func TestTheWindowIsTheSpanActuallyCovered(t *testing.T) {
	c := newClocked(t)
	early, late := slowThenFast()
	c.at(0, early)
	c.at(40*time.Second, late)
	// Asked for 5 minutes, but only 40 seconds of history exist. It says 40s, not 5m.
	ex := c.ExplainOver("db", t0.Add(40*time.Second), 5*time.Minute)
	if ex.Window != "40s" || !strings.Contains(ex.Basis, "last 40s") {
		t.Fatalf("window %q basis %q", ex.Window, ex.Basis)
	}
}

func TestAQuietWindowDoesNotReadAsADetachedProgram(t *testing.T) {
	c := newClocked(t)
	busy := map[uint32]aggregate.Counters{
		101: {BlockIssues: 900, BlockWriteOps: 900, BlockWrite: bucket(map[int]uint64{15: 900}), OnCPUNs: 5, Entries: 3, Exits: map[uint32]uint64{12: 3}},
	}
	c.at(0, busy)
	c.at(30*time.Second, busy) // nothing at all happened in the window
	c.at(60*time.Second, busy)
	ex := c.ExplainOver("db", t0.Add(60*time.Second), time.Minute)
	if f := causeOf(ex, "not_measured"); f != nil {
		t.Fatalf("an idle minute looked like a detached program: %+v", ex.Findings)
	}
	if f := causeOf(ex, "no_host_cause"); f == nil {
		t.Fatalf("an idle, healthy VM should say no host cause: %+v", ex.Findings)
	}
	for _, e := range ex.Evidence {
		if strings.Contains(e, "not populated") {
			t.Fatalf("%q", e)
		}
	}
}

func TestACounterResetInTheWindowIsNotAHugeNumber(t *testing.T) {
	c := newClocked(t)
	c.at(0, map[uint32]aggregate.Counters{101: {BlockWriteOps: 900000, BlockIssues: 900000, BlockWrite: bucket(map[int]uint64{27: 900000}), OnCPUNs: 1}})
	// The vCPU thread was replaced: its counters started again from zero.
	fresh := map[uint32]aggregate.Counters{101: {BlockWriteOps: 40, BlockIssues: 40, BlockWrite: bucket(map[int]uint64{15: 40}), OnCPUNs: 2}}
	c.at(30*time.Second, fresh)
	c.at(60*time.Second, fresh)
	ex := c.ExplainOver("db", t0.Add(60*time.Second), time.Minute)
	if causeOf(ex, "storage_latency") != nil {
		t.Fatalf("a reset counter was read as slow I/O: %+v", ex.Findings)
	}
}

func TestVCPUContentionUsesTheWindowsRunQueueDelay(t *testing.T) {
	c := newClocked(t)
	calm := map[uint32]aggregate.Counters{101: {OnCPUNs: 1, WakeupCount: 1000, SchedHist: bucket(map[int]uint64{11: 1000})}}
	starved := map[uint32]aggregate.Counters{101: {OnCPUNs: 2, WakeupCount: 1200, SchedHist: bucket(map[int]uint64{11: 1000, 25: 200})}} // 200 waits of ~67 ms
	c.at(0, calm)
	c.at(30*time.Second, starved)
	c.at(60*time.Second, starved)
	f := causeOf(c.ExplainOver("db", t0.Add(60*time.Second), time.Minute), "host_cpu_contention")
	if f == nil || f.Confidence != "high" || !strings.Contains(f.Evidence[0], "vCPU thread 101") {
		t.Fatalf("%+v", f)
	}
}

func TestHistoryIsBoundedAndRateLimited(t *testing.T) {
	c := newClocked(t)
	by := map[uint32]aggregate.Counters{101: {OnCPUNs: 1}}
	// Scans arrive every 2s; a snapshot should be kept only every snapEvery.
	for i := 0; i < 30; i++ {
		c.at(time.Duration(i*2)*time.Second, by)
	}
	if n := len(c.history); n < 5 || n > 7 { // 60s of scans, one snapshot per 10s
		t.Fatalf("%d snapshots for 60s of scans", n)
	}
	// A long run must not grow without bound.
	for i := 30; i < 5000; i++ {
		c.at(time.Duration(i*2)*time.Second, by)
	}
	if n := len(c.history); n > int(snapKeep/snapEvery)+2 {
		t.Fatalf("history grew to %d snapshots", n)
	}
	// A snapshot is a copy: changing the live counters afterwards does not rewrite it.
	live := map[uint32]aggregate.Counters{101: {OnCPUNs: 7, KVMLat: bucket(map[int]uint64{3: 1})}}
	c.at(20000*time.Second, live)
	live[101].KVMLat[3] = 999
	last := c.history[len(c.history)-1].threads["db"][101]
	if last.KVMLat[3] != 1 {
		t.Fatal("a snapshot shares memory with the counters it was taken from")
	}
}

func TestAnUnknownVMIsNeverWindowed(t *testing.T) {
	c := newClocked(t)
	early, late := slowThenFast()
	c.at(0, early)
	c.at(60*time.Second, late)
	ex := c.ExplainOver("nope", t0.Add(60*time.Second), time.Minute)
	if len(ex.Findings) != 1 || ex.Findings[0].Cause != "unknown_vm" {
		t.Fatalf("%+v", ex.Findings)
	}
}

func TestCPUPreemptionUsesTheWindowsPreemptionNotTheLifetimes(t *testing.T) {
	c := newClocked(t)
	// Long ago the vCPU lost 40 s of CPU to a neighbour. In this window it lost 6 s, mostly to web.
	base := map[uint32]aggregate.Counters{101: {OnCPUNs: 20_000 * ms, WakeupCount: 1, PreemptNs: 40_000 * ms, PreemptCount: 400,
		Preemptors: map[string]uint64{"vm:web": 40_000 * ms}}}
	cur := map[uint32]aggregate.Counters{101: {OnCPUNs: 40_000 * ms, WakeupCount: 2, PreemptNs: 46_000 * ms, PreemptCount: 460,
		Preemptors: map[string]uint64{"vm:web": 45_000 * ms, "ksoftirqd": 1_000 * ms}}}
	c.at(0, base)
	c.at(30*time.Second, cur)
	c.at(60*time.Second, cur)
	f := causeOf(c.ExplainOver("db", t0.Add(60*time.Second), time.Minute), "cpu_preempted")
	if f == nil {
		t.Fatal("no finding")
	}
	all := strings.Join(f.Evidence, " ")
	if !strings.Contains(all, "6 s") || !strings.Contains(all, "60 preemptions") || !strings.Contains(all, "VM web (5 s)") || strings.Contains(all, "46 s") {
		t.Fatalf("it must report the window's own numbers: %s", all)
	}
	// Over the lifetime it is everything since the daemon attached.
	f = causeOf(c.ExplainOver("db", t0.Add(60*time.Second), 0), "cpu_preempted")
	if f == nil || !strings.Contains(strings.Join(f.Evidence, " "), "46 s") {
		t.Fatalf("%+v", f)
	}
}
