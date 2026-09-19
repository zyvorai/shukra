package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

// dropsWorld is a state with one VM "db" on tap0, and sources whose numbers a test can change.
type dropsWorld struct {
	*clocked
	tapDropped uint64
	drops      map[string]uint64 // reason -> count on tap0
}

func newDropsWorld(t *testing.T) *dropsWorld {
	t.Helper()
	w := &dropsWorld{clocked: newClocked(t), drops: map[string]uint64{}}
	w.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}, Taps: []string{"tap0"}}})
	w.SetPrograms([]Program{{Name: "tap", Status: "attached", Detail: "1 taps"}, {Name: "drops", Status: "attached", Detail: "1 hooks"}})
	w.SetTapSource(func() []TapStat { return []TapStat{{Name: "tap0", DroppedPkts: w.tapDropped}} })
	w.SetDropSource(func() []DropStat {
		var out []DropStat
		for r, n := range w.drops {
			out = append(out, DropStat{Tap: "tap0", Reason: r, Count: n, Location: "__netif_receive_skb_core"})
		}
		out = append(out, DropStat{Tap: "orphan", Reason: "TC_INGRESS", Count: 999}) // a tap no VM owns
		return out
	})
	w.dropInputs() // the daemon's first look, with Shukra having dropped nothing yet
	return w
}

func tapOf(t *testing.T, taps []DropTap) DropTap {
	t.Helper()
	if len(taps) != 1 || taps[0].Tap != "tap0" || taps[0].VM != "db" {
		t.Fatalf("expected only db's tap0, got %+v", taps)
	}
	return taps[0]
}

func TestShukrasOwnDropsAreSubtractedFromTheKernelsCount(t *testing.T) {
	w := newDropsWorld(t)
	// Isolation dropped 40 packets; the kernel saw them as TC_INGRESS. Another program dropped 25 more
	// as TC_INGRESS, and 7 were dropped because the guest's queue was full.
	w.tapDropped = 40
	w.drops = map[string]uint64{"TC_INGRESS": 65, "FULL_RING": 7}
	rows, taps := w.Drops("")
	d := tapOf(t, taps)
	if d.KernelDrops != 72 || d.ShukraDropped != 40 || d.OtherDrops != 25 || d.QueueFull != 7 {
		t.Fatalf("%+v", d)
	}
	if len(d.Reasons) != 2 || d.Reasons[0].Reason != "TC_INGRESS" {
		t.Fatalf("reasons must be largest first: %+v", d.Reasons)
	}
	if len(rows) != 2 || rows[0].VM != "db" || rows[0].Location != "__netif_receive_skb_core" {
		t.Fatalf("the orphan tap must not appear, and rows carry the location: %+v", rows)
	}
}

// The tap program's counters are pinned and outlive a daemon restart; the kernel's drop counts do not.
// If the lifetime figure were subtracted from the fresh one, isolation that happened before the restart
// would hide another program's drops.
func TestIsolationBeforeARestartDoesNotHideAnotherProgramsDrops(t *testing.T) {
	w := &dropsWorld{clocked: newClocked(t), drops: map[string]uint64{}}
	w.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}, Taps: []string{"tap0"}}})
	w.SetPrograms([]Program{{Name: "tap", Status: "attached"}, {Name: "drops", Status: "attached"}})
	w.SetTapSource(func() []TapStat { return []TapStat{{Name: "tap0", DroppedPkts: w.tapDropped}} })
	w.SetDropSource(func() []DropStat {
		var out []DropStat
		for r, n := range w.drops {
			out = append(out, DropStat{Tap: "tap0", Reason: r, Count: n})
		}
		return out
	})
	w.tapDropped = 13 // isolation dropped these before this daemon started; the kernel counts none of them
	if d := tapOf(t, mustTaps(w)); d.OtherDrops != 0 || d.ShukraDropped != 0 {
		t.Fatalf("nothing has happened since the daemon started: %+v", d)
	}
	w.drops = map[string]uint64{"TC_INGRESS": 20} // a tc filter, not Shukra
	if d := tapOf(t, mustTaps(w)); d.OtherDrops != 20 || d.ShukraDropped != 0 {
		t.Fatalf("all 20 are another program's: %+v", d)
	}
	w.tapDropped = 18 // and isolation drops five more, which are the kernel's TC_INGRESS too
	w.drops = map[string]uint64{"TC_INGRESS": 25}
	if d := tapOf(t, mustTaps(w)); d.OtherDrops != 20 || d.ShukraDropped != 5 {
		t.Fatalf("five are Shukra's and twenty are not: %+v", d)
	}
	w.tapDropped = 2 // the tap was detached and attached again: its counter starts over
	w.drops = map[string]uint64{"TC_INGRESS": 27}
	if d := tapOf(t, mustTaps(w)); d.ShukraDropped != 2 {
		t.Fatalf("a counter that went backwards starts again from zero: %+v", d)
	}
}

func TestIsolationAloneLeavesNothingUnexplained(t *testing.T) {
	w := newDropsWorld(t)
	w.tapDropped = 300
	w.drops = map[string]uint64{"TC_INGRESS": 180, "TC_EGRESS": 120}
	if d := tapOf(t, mustTaps(w)); d.OtherDrops != 0 {
		t.Fatalf("Shukra's own drops were blamed on something else: %+v", d)
	}
	// Shukra cannot have explained more than the kernel counted as TC drops.
	w.tapDropped = 1000
	if d := tapOf(t, mustTaps(w)); d.OtherDrops != 0 {
		t.Fatalf("%+v", d)
	}
}

func mustTaps(w *dropsWorld) []DropTap { _, taps := w.Drops(""); return taps }

func TestNothingIsSaidAboutDropsWhileTheProgramIsNotMeasuring(t *testing.T) {
	w := newDropsWorld(t)
	w.drops = map[string]uint64{"TC_INGRESS": 500}
	w.SetPrograms([]Program{{Name: "drops", Status: "detached", Detail: "skb:kfree_skb has no drop reason"}})
	if rows, taps := w.Drops(""); rows != nil || taps != nil {
		t.Fatalf("invented an answer: %+v %+v", rows, taps)
	}
	if taps, over := w.DropTapsOver("", w.now, time.Minute); taps != nil || over != "" {
		t.Fatalf("%+v %q", taps, over)
	}
	if v := w.TapTotals()["db"]; v.DropsOK || v.ForeignDrops != 0 {
		t.Fatalf("foreign drops reported with no program measuring: %+v", v)
	}
}

func TestAWindowCountsOnlyWhatDroppedInsideIt(t *testing.T) {
	w := newDropsWorld(t)
	// A lot dropped long ago, then 30 more in the last minute.
	w.drops = map[string]uint64{"TC_INGRESS": 5000}
	w.at(0, nil)
	w.drops = map[string]uint64{"TC_INGRESS": 5000}
	w.at(5*time.Minute, nil)
	w.drops = map[string]uint64{"TC_INGRESS": 5030}
	w.at(6*time.Minute, nil)
	taps, over := w.DropTapsOver("", w.now, time.Minute)
	if over == "lifetime" {
		t.Fatalf("there was history to window on")
	}
	if d := tapOf(t, taps); d.OtherDrops != 30 {
		t.Fatalf("the window must hold 30, not the lifetime 5030: %+v (over %s)", d, over)
	}
	life, over := w.DropTapsOver("", w.now, 0)
	if over != "lifetime" || tapOf(t, life).OtherDrops != 5030 {
		t.Fatalf("%+v %s", life, over)
	}
}

func TestTooLittleHistoryFallsBackToLifetimeForDrops(t *testing.T) {
	w := newDropsWorld(t)
	w.drops = map[string]uint64{"TC_INGRESS": 80}
	w.at(0, nil)
	w.at(5*time.Second, nil)
	taps, over := w.DropTapsOver("", w.now, time.Minute)
	if over != "lifetime" || tapOf(t, taps).OtherDrops != 80 {
		t.Fatalf("%+v %s", taps, over)
	}
}

func TestADropCounterResetInTheWindowIsNotAHugeNumber(t *testing.T) {
	w := newDropsWorld(t)
	w.drops = map[string]uint64{"TC_INGRESS": 9000}
	w.at(0, nil)
	w.at(time.Minute, nil)
	w.drops = map[string]uint64{"TC_INGRESS": 12} // the daemon reloaded its maps
	w.at(2*time.Minute, nil)
	taps, _ := w.DropTapsOver("", w.now, time.Minute)
	if d := tapOf(t, taps); d.OtherDrops != 12 {
		t.Fatalf("a reset must read as what happened since it, not as 2^64 - 8988: %+v", d)
	}
}

func TestDoctorNamesTheVMTapAndReasonWhenSomethingElseIsDropping(t *testing.T) {
	w := newDropsWorld(t)
	st := healthy(t)
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	st.SetPrograms([]Program{
		{Name: "kvm", Status: "attached", Detail: "4 hooks"}, {Name: "tap", Status: "attached", Detail: "1 taps"},
		{Name: "drops", Status: "attached", Detail: "1 hooks"},
	})
	st.SetTapSource(func() []TapStat { return []TapStat{{Name: "tap0", DroppedPkts: 0}} })
	st.SetDropSource(func() []DropStat {
		return []DropStat{{Tap: "tap0", Reason: "TC_INGRESS", Count: 58}, {Tap: "tap0", Reason: "FULL_RING", Count: 11}}
	})
	_ = w
	checks := st.Doctor()
	c := byID(checks, "vm-drops-not-shukra")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "1 VMs") || !strings.Contains(c.Detail, "db (tap0: TC_INGRESS 58)") ||
		!strings.Contains(c.Fix, "bpftool net show dev") {
		t.Fatalf("%+v", c)
	}
	n := byID(checks, "vm-nic-not-consumed")
	if n == nil || n.Status != "warn" || !strings.Contains(n.Detail, "db (tap0: 11)") {
		t.Fatalf("%+v", n)
	}
	if strings.Contains(c.Detail, "FULL_RING") {
		t.Fatalf("a full queue must be reported once, as the guest not reading: %s", c.Detail)
	}
}

func TestDoctorIsQuietWhenDropsAreShukrasOwnFewOrUnmeasured(t *testing.T) {
	st := healthy(t)
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	attached := []Program{{Name: "tap", Status: "attached", Detail: "1 taps"}, {Name: "drops", Status: "attached", Detail: "1 hooks"}}
	st.SetPrograms(attached)
	var isolated uint64
	st.SetTapSource(func() []TapStat { return []TapStat{{Name: "tap0", DroppedPkts: isolated}} })
	st.SetDropSource(func() []DropStat { return nil })
	st.dropInputs() // the daemon's first look, before anything is dropped
	isolated = 100
	st.SetDropSource(func() []DropStat { return []DropStat{{Tap: "tap0", Reason: "TC_INGRESS", Count: 103}} }) // 3 of skew
	for _, c := range st.Doctor() {
		if strings.HasPrefix(c.ID, "vm-drops") || c.ID == "vm-nic-not-consumed" {
			t.Fatalf("%+v", c)
		}
	}
	st.SetDropSource(func() []DropStat { return []DropStat{{Tap: "tap0", Reason: "TC_INGRESS", Count: 5000}} })
	st.SetPrograms([]Program{{Name: "tap", Status: "attached", Detail: "1 taps"}, {Name: "drops", Status: "detached", Detail: "no drop reason"}})
	if byID(st.Doctor(), "vm-drops-not-shukra") != nil {
		t.Fatal("reported drops the program was not measuring")
	}
}

func TestExplainGivesTheDropsAsACause(t *testing.T) {
	w := newDropsWorld(t)
	w.SetPrograms([]Program{{Name: "kvm", Status: "attached", Detail: "4 hooks"}, {Name: "tap", Status: "attached", Detail: "1 taps"}, {Name: "drops", Status: "attached", Detail: "1 hooks"}})
	w.drops = map[string]uint64{"TC_INGRESS": 60}
	w.at(0, map[uint32]aggregate.Counters{100: {Exits: map[uint32]uint64{1: 10}, Entries: 10}})
	ex := w.ExplainOver("db", w.now, time.Minute)
	f := causeOf(ex, "guest_traffic_dropped")
	if f == nil || !strings.Contains(f.Evidence[0], "60 packets") {
		t.Fatalf("%+v", ex.Findings)
	}
}
