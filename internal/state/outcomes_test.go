package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

func TestConnectionsAreFailingOnlyWithEnoughOfThemAndMostFailing(t *testing.T) {
	for name, c := range map[string]struct {
		o    Outcomes
		want bool
	}{
		"most refused":                   {Outcomes{OutOK: 3, OutRefused: 20}, true},
		"most never answered":            {Outcomes{OutOK: 2, OutTimeout: 12}, true},
		"exactly half":                   {Outcomes{OutOK: 10, OutRefused: 5, OutTimeout: 5}, true},
		"a few refusals":                 {Outcomes{OutOK: 90, OutRefused: 6}, false},
		"too few to say":                 {Outcomes{OutRefused: 9}, false},
		"all fine":                       {Outcomes{OutOK: 500}, false},
		"blocked is not failing":         {Outcomes{OutOK: 1, OutBlocked: 500}, false}, // isolation did that, on purpose
		"inbound is not the guest's own": {Outcomes{InRefused: 500, InIgnored: 500}, false},
	} {
		got, what := connectFailing(c.o)
		if got != c.want {
			t.Errorf("%s: got %v (%s), want %v", name, got, what, c.want)
		}
	}
	_, what := connectFailing(Outcomes{OutOK: 3, OutRefused: 20, OutTimeout: 4})
	if !strings.Contains(what, "24 of 27") || !strings.Contains(what, "20 refused") || !strings.Contains(what, "4 never answered") {
		t.Fatalf("%q", what)
	}
}

// outcomesWorld is a state with one VM "db" on tap0 whose handshake counters a test can change.
type outcomesWorld struct {
	*clocked
	o Outcomes
}

func newOutcomesWorld(t *testing.T) *outcomesWorld {
	t.Helper()
	w := &outcomesWorld{clocked: newClocked(t)}
	w.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}, Taps: []string{"tap0"}}})
	w.SetPrograms([]Program{{Name: "kvm", Status: "attached", Detail: "4 hooks"}, {Name: "tap", Status: "attached", Detail: "1 taps"}})
	w.SetTapSource(func() []TapStat {
		return []TapStat{{Name: "tap0", Outcomes: w.o, HandshakeHist: make([]uint64, 64)}}
	})
	return w
}

func TestAWindowOfOutcomesCountsOnlyWhatHappenedInsideIt(t *testing.T) {
	w := newOutcomesWorld(t)
	w.o = Outcomes{OutOK: 4000} // a long, healthy history
	w.at(0, nil)
	w.at(5*time.Minute, nil)
	w.o = Outcomes{OutOK: 4003, OutRefused: 30} // then thirty refusals in the last minute
	w.at(6*time.Minute, nil)
	oc, over := w.OutcomesOver("", w.now, time.Minute)
	if over == "lifetime" {
		t.Fatal("there was history to window on")
	}
	got := oc["db"]
	if got.OutRefused != 30 || got.OutOK != 3 {
		t.Fatalf("the window holds 30 refusals and 3 successes, not the lifetime: %+v", got)
	}
	if ok, _ := connectFailing(got); !ok {
		t.Fatal("thirty refusals against three successes must read as failing in the window, however healthy the past was")
	}
	life, over := w.OutcomesOver("", w.now, 0)
	if over != "lifetime" || life["db"].OutOK != 4003 {
		t.Fatalf("%+v %s", life, over)
	}
	if ok, _ := connectFailing(life["db"]); ok {
		t.Fatal("over the whole life the VM is healthy")
	}
}

func TestOutcomesAreNotInventedWhileTheTapProgramIsNotOn(t *testing.T) {
	w := newOutcomesWorld(t)
	w.o = Outcomes{OutRefused: 100}
	w.SetPrograms([]Program{{Name: "tap", Status: "detached", Detail: "TCX needs Linux 6.6 or newer"}})
	if oc, over := w.OutcomesOver("", w.now, time.Minute); oc != nil || over != "" {
		t.Fatalf("%+v %q", oc, over)
	}
	if v := w.TapTotals()["db"]; v.OutcomesOK || v.OutRefused != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestTapTotalsCarryTheOutcomesTheRulesRead(t *testing.T) {
	w := newOutcomesWorld(t)
	w.o = Outcomes{OutRefused: 7, OutTimeout: 3, InSyn: 40}
	v := w.TapTotals()["db"]
	if !v.OutcomesOK || v.OutRefused != 7 || v.OutTimeout != 3 || v.InSyn != 40 {
		t.Fatalf("%+v", v)
	}
	if v.DropsOK {
		t.Fatal("drops were reported as measured with no drops program")
	}
}

func TestDoctorNamesAVMWhoseConnectionsMostlyFail(t *testing.T) {
	st := healthy(t)
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}, {Name: "web", Taps: []string{"tap1"}}})
	st.SetPrograms([]Program{{Name: "kvm", Status: "attached", Detail: "4 hooks"}, {Name: "tap", Status: "attached", Detail: "2 taps"}})
	st.SetTapSource(func() []TapStat {
		return []TapStat{
			{Name: "tap0", Outcomes: Outcomes{OutOK: 2, OutRefused: 30, OutTimeout: 5}},
			{Name: "tap1", Outcomes: Outcomes{OutOK: 400, OutRefused: 3}},
		}
	})
	c := byID(st.Doctor(), "vm-connects-failing")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "1 VMs") || !strings.Contains(c.Detail, "db (35 of 37") || strings.Contains(c.Detail, "web") ||
		!strings.Contains(c.Fix, "Never answered") {
		t.Fatalf("%+v", c)
	}
	st.SetPrograms([]Program{{Name: "tap", Status: "detached", Detail: "no VM tap interfaces"}})
	if byID(st.Doctor(), "vm-connects-failing") != nil {
		t.Fatal("reported failing connects with the tap program off")
	}
}

func TestExplainGivesFailingConnectionsAsACause(t *testing.T) {
	w := newOutcomesWorld(t)
	w.o = Outcomes{OutOK: 1, OutTimeout: 40}
	w.at(0, map[uint32]aggregate.Counters{100: {Exits: map[uint32]uint64{1: 10}, Entries: 10}})
	f := causeOf(w.ExplainOver("db", w.now, time.Minute), "guest_connects_failing")
	if f == nil || f.Confidence != "medium" || !strings.Contains(f.Evidence[0], "40 never answered") || !strings.Contains(f.Summary, "blocked egress") {
		t.Fatalf("%+v", f)
	}
}
