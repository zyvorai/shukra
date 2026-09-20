package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

const sec = uint64(1_000_000_000)

// advisorWith is a state with one VM "big" that has n vCPU threads (101..) on a host of the given CPU vendor.
func advisorWith(t *testing.T, vcpus int, vendor string) *clocked {
	t.Helper()
	c := newClocked(t)
	info := []identity.Thread{{TID: 100, Comm: "qemu", Role: "main"}}
	threads := []int{100}
	for i := 0; i < vcpus; i++ {
		info = append(info, identity.Thread{TID: 101 + i, Comm: "CPU n/KVM", Role: "vcpu"})
		threads = append(threads, 101+i)
	}
	c.SetVMs([]identity.VM{{Name: "big", PID: 100, Threads: threads, ThreadInfo: info}})
	c.SetCPUVendor(vendor)
	return c
}

// counters spreads a VM's totals over its vCPU threads: halt time (HLT exits), on-CPU time and preempted time.
func spread(vcpus int, halt, onCPU, preempt uint64, rq map[int]uint64) map[uint32]aggregate.Counters {
	out := map[uint32]aggregate.Counters{100: {OnCPUNs: 1, WakeupCount: 1}}
	for i := 0; i < vcpus; i++ {
		out[uint32(101+i)] = aggregate.Counters{
			Exits: map[uint32]uint64{12: 100}, ExitNs: map[uint32]uint64{12: halt / uint64(vcpus)}, Entries: 100,
			OnCPUNs: onCPU / uint64(vcpus), WakeupCount: 1000, PreemptNs: preempt / uint64(vcpus), PreemptCount: 5,
			SchedHist: bucket(rq),
		}
	}
	return out
}

// over runs the state for span with the given totals since a zero start, then asks the advisor.
func adviceFor(c *clocked, span time.Duration, totals map[uint32]aggregate.Counters) AdviceRow {
	c.at(0, map[uint32]aggregate.Counters{100: {OnCPUNs: 1, WakeupCount: 1}})
	c.at(span, totals)
	rep := c.Advise("big", t0.Add(span), DefaultAdviceWindow)
	if len(rep.Rows) != 1 {
		panic("no row")
	}
	return rep.Rows[0]
}

func kinds(r AdviceRow) []string {
	var out []string
	for _, a := range r.Advice {
		out = append(out, a.Kind)
	}
	return out
}

func has(r AdviceRow, kind string) *Advice {
	for i := range r.Advice {
		if r.Advice[i].Kind == kind {
			return &r.Advice[i]
		}
	}
	return nil
}

func TestAnIdleVMWithManyVCPUsIsOverprovisionedAndTheAdviceSaysHowManyWouldDo(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	// 4 vCPUs for 240 s = 960 s of capacity: halted 900 s (94%), on CPU 30 s (3%): about 0.13 of a vCPU.
	r := adviceFor(c, 240*time.Second, spread(4, 900*sec, 30*sec, 0, map[int]uint64{11: 100}))
	a := has(r, "overprovisioned")
	if a == nil || a.Confidence != "medium" || !strings.Contains(a.Summary, "4 vCPUs") || !strings.Contains(a.Summary, "1 would leave") {
		t.Fatalf("%+v", r.Advice)
	}
	if r.VCPUs != 4 || !r.IdleAvailable || r.IdleFraction < 0.93 || r.IdleFraction > 0.95 || r.BusyFraction < 0.03 || r.BusyFraction > 0.04 {
		t.Fatalf("the numbers behind the advice: %+v", r)
	}
	if !strings.Contains(a.Evidence[0], "lower bound") {
		t.Fatalf("the caveat must travel with the advice: %s", a.Evidence[0])
	}
}

func TestAShortWindowIsALowConfidenceSample(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	r := adviceFor(c, 100*time.Second, spread(4, 370*sec, 12*sec, 0, map[int]uint64{11: 100}))
	if a := has(r, "overprovisioned"); a == nil || a.Confidence != "low" {
		t.Fatalf("%+v", r.Advice)
	}
}

func TestABusyVMThatIsPreemptedIsStarvedAndIsNeverToldToAddVCPUs(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	// busy 700 s of 960 (73%), preempted 200 s (22% of what it wanted), and a vCPU that waited ~67 ms.
	r := adviceFor(c, 240*time.Second, spread(4, 100*sec, 700*sec, 200*sec, map[int]uint64{25: 50}))
	a := has(r, "starved")
	if a == nil || a.Confidence != "high" || !strings.Contains(a.Summary, "reduce what it competes with") {
		t.Fatalf("%+v", r.Advice)
	}
	if has(r, "overprovisioned") != nil || has(r, "no_change") != nil {
		t.Fatalf("a starved VM is not also over-provisioned: %v", kinds(r))
	}
	if strings.Contains(strings.ToLower(a.Summary), "add a vcpu") || strings.Contains(strings.ToLower(a.Summary), "give it more vcpus") {
		t.Fatalf("more vCPUs make it worse: %s", a.Summary)
	}
}

func TestAMiddlingVMGetsNoChangeAndItsNumbers(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	// Halted half the time and busy 42%: neither over-provisioned nor starved.
	r := adviceFor(c, 240*time.Second, spread(4, 500*sec, 400*sec, 10*sec, map[int]uint64{11: 100}))
	if has(r, "starved") != nil || has(r, "overprovisioned") != nil {
		t.Fatalf("%v", kinds(r))
	}
	if a := has(r, "no_change"); a == nil || !strings.Contains(a.Evidence[0], "%") {
		t.Fatalf("no_change carries its numbers: %+v", r.Advice)
	}
}

func TestOnACPUWhereHaltIsNotNamedNoClaimIsMadeAboutIdleness(t *testing.T) {
	c := advisorWith(t, 4, "AuthenticAMD")
	r := adviceFor(c, 240*time.Second, spread(4, 900*sec, 30*sec, 0, map[int]uint64{11: 100}))
	if r.IdleAvailable || has(r, "overprovisioned") != nil || has(r, "nearly_idle") != nil {
		t.Fatalf("%+v", r)
	}
	if a := has(r, "idle_unavailable"); a == nil || !strings.Contains(a.Summary, "only named on Intel") {
		t.Fatalf("%+v", r.Advice)
	}
	// Starvation does not need halt time, so it is still reported on such a host.
	c2 := advisorWith(t, 4, "AuthenticAMD")
	r2 := adviceFor(c2, 240*time.Second, spread(4, 100*sec, 700*sec, 200*sec, map[int]uint64{25: 50}))
	if has(r2, "starved") == nil {
		t.Fatalf("%v", kinds(r2))
	}
}

func TestASingleVCPUThatIsAlmostAlwaysHaltedIsAConsolidationCandidate(t *testing.T) {
	c := advisorWith(t, 1, "GenuineIntel")
	r := adviceFor(c, 240*time.Second, spread(1, 232*sec, 3*sec, 0, map[int]uint64{11: 10}))
	if has(r, "nearly_idle") == nil || has(r, "overprovisioned") != nil {
		t.Fatalf("one vCPU cannot be reduced: %v", kinds(r))
	}
}

func TestTheAdvisorSaysNothingItCannotStandOn(t *testing.T) {
	// Not enough history.
	c := advisorWith(t, 4, "GenuineIntel")
	c.at(0, spread(4, 1*sec, 1*sec, 0, nil))
	c.at(5*time.Second, spread(4, 2*sec, 2*sec, 0, nil))
	r := c.Advise("big", t0.Add(5*time.Second), DefaultAdviceWindow).Rows[0]
	if a := has(r, "not_enough_data"); a == nil || len(r.Advice) != 1 || r.Window != "none" {
		t.Fatalf("%+v", r)
	}
	// Not measured by the programs at all.
	empty := advisorWith(t, 4, "GenuineIntel")
	if r := empty.Advise("big", t0, DefaultAdviceWindow).Rows[0]; has(r, "not_enough_data") == nil || !strings.Contains(r.Advice[0].Summary, "not measured") {
		t.Fatalf("%+v", r)
	}
	// No vCPU thread known.
	none := advisorWith(t, 0, "GenuineIntel")
	none.at(0, spread(0, 0, 0, 0, nil))
	none.at(60*time.Second, map[uint32]aggregate.Counters{100: {OnCPUNs: 9, WakeupCount: 9, Exits: map[uint32]uint64{12: 1}, Entries: 1}})
	if r := none.Advise("big", t0.Add(60*time.Second), DefaultAdviceWindow).Rows[0]; has(r, "not_enough_data") == nil || !strings.Contains(r.Advice[0].Summary, "vCPU thread") {
		t.Fatalf("%+v", r)
	}
	// An unknown VM has no row.
	if rows := c.Advise("nobody", t0, DefaultAdviceWindow).Rows; rows == nil || len(rows) != 0 {
		t.Fatalf("%+v", rows)
	}
}

func TestIdleAndBusyAreNeverMoreThanAWholeWindow(t *testing.T) {
	c := advisorWith(t, 2, "GenuineIntel")
	// Halt time larger than the capacity (halt polling, clock skew) must clamp, not exceed 100%.
	r := adviceFor(c, 100*time.Second, spread(2, 900*sec, 900*sec, 0, map[int]uint64{11: 10}))
	if r.IdleFraction != 1 || r.BusyFraction != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestTheSuggestedSizeLeavesTwiceTheHeadroomItUsed(t *testing.T) {
	c := advisorWith(t, 8, "GenuineIntel")
	// 8 vCPUs, on CPU 12.5% (one vCPU's worth), halted 86%: twice one vCPU is 2.
	r := adviceFor(c, 240*time.Second, spread(8, 1650*sec, 240*sec, 0, map[int]uint64{11: 100}))
	a := has(r, "overprovisioned")
	if a == nil || !strings.Contains(a.Summary, "used about 1.0 of them. 2 would leave") {
		t.Fatalf("%+v", r.Advice)
	}
}

func TestAMostlyIdleVMIsNotStarvedJustBecauseAFewPreemptionsAreALargeShareOfLittle(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	// 10 s on CPU and 5 s preempted is a 33% share, but the vCPUs were 1% busy: nothing was being starved.
	r := adviceFor(c, 240*time.Second, spread(4, 930*sec, 10*sec, 5*sec, map[int]uint64{11: 100}))
	if has(r, "starved") != nil || r.PreemptShare < 0.3 {
		t.Fatalf("%v share %.2f", kinds(r), r.PreemptShare)
	}
}

func TestOnlyHaltTimeCountsAsIdleAndOnlyVCPUThreadsCountAsBusy(t *testing.T) {
	c := advisorWith(t, 4, "GenuineIntel")
	tot := spread(4, 100*sec, 30*sec, 0, map[int]uint64{11: 100})
	for tid := uint32(101); tid <= 104; tid++ { // a lot of time in EPT violations: host work, not idleness
		cc := tot[tid]
		cc.Exits[48], cc.ExitNs[48] = 10, 200*sec
		tot[tid] = cc
	}
	main := tot[100] // the QEMU main thread and iothreads are busy too, and are not the guest's CPUs
	main.OnCPUNs = 800 * sec
	tot[100] = main
	r := adviceFor(c, 240*time.Second, tot)
	if r.IdleFraction > 0.11 {
		t.Fatalf("EPT violations are not idle time: %.2f", r.IdleFraction)
	}
	if r.BusyFraction > 0.04 {
		t.Fatalf("the QEMU main thread's CPU time is not the guest's: %.2f", r.BusyFraction)
	}
}

// Seen on a real host: three-vCPU VMs read exactly one third or two thirds halted, because the other vCPUs never
// execute HLT (offline in the guest, or idling with MWAIT). "No change" must show that gap instead of hiding it.
func TestNoChangeShowsTheShareThatIsNeitherHaltedNorBusyAndSaysWhatItMeans(t *testing.T) {
	c := advisorWith(t, 3, "GenuineIntel")
	r := adviceFor(c, 240*time.Second, spread(3, 240*sec, 4*sec, 0, map[int]uint64{11: 100})) // one vCPU's worth halted
	if r.UnaccountedFraction < 0.65 || r.UnaccountedFraction > 0.68 {
		t.Fatalf("unaccounted %.2f", r.UnaccountedFraction)
	}
	a := has(r, "no_change")
	if a == nil || len(a.Evidence) != 2 || !strings.Contains(a.Evidence[1], "neither halted nor on a CPU") || !strings.Contains(a.Evidence[1], "not proof") {
		t.Fatalf("%+v", r.Advice)
	}
	// A VM whose time is accounted for does not get the caveat, and an unavailable idle figure is never a share.
	full := advisorWith(t, 4, "GenuineIntel")
	r2 := adviceFor(full, 240*time.Second, spread(4, 500*sec, 400*sec, 10*sec, map[int]uint64{11: 100}))
	if a := has(r2, "no_change"); a == nil || len(a.Evidence) != 1 {
		t.Fatalf("%+v", r2.Advice)
	}
	amd := advisorWith(t, 4, "AuthenticAMD")
	if r3 := adviceFor(amd, 240*time.Second, spread(4, 500*sec, 400*sec, 0, map[int]uint64{11: 100})); r3.UnaccountedFraction != 0 {
		t.Fatalf("%.2f", r3.UnaccountedFraction)
	}
}
