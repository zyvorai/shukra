package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

// fakeEnforcer records what it was asked to do.
type fakeEnforcer struct {
	ok       bool
	why      string
	allow    []string
	isolated map[string]bool
	failOn   map[string]bool
	calls    []string
}

func newFake() *fakeEnforcer {
	return &fakeEnforcer{ok: true, allow: []string{"10.0.0.1/32"}, isolated: map[string]bool{}, failOn: map[string]bool{}}
}

func (f *fakeEnforcer) Available() (bool, string) { return f.ok, f.why }
func (f *fakeEnforcer) AllowList() []string       { return f.allow }
func (f *fakeEnforcer) Isolated(t string) bool    { return f.isolated[t] }
func (f *fakeEnforcer) set(op string, taps []string, on bool) ([]string, error) {
	var done, failed []string
	for _, t := range taps {
		f.calls = append(f.calls, op+":"+t)
		if f.failOn[t] {
			failed = append(failed, t+" not attached")
			continue
		}
		f.isolated[t] = on
		done = append(done, t)
	}
	if len(failed) > 0 {
		return done, errors.New(strings.Join(failed, "; "))
	}
	return done, nil
}
func (f *fakeEnforcer) Isolate(t []string) ([]string, error) { return f.set("isolate", t, true) }
func (f *fakeEnforcer) Release(t []string) ([]string, error) { return f.set("release", t, false) }

func stateWithVM(taps ...string) (*State, *fakeEnforcer) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Taps: taps}})
	f := newFake()
	st.SetEnforcer(f)
	return st, f
}

func TestNoEnforcerKeepsTheRecordOnlyBehaviour(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	got := st.Isolate("db", "cli")
	if got.Applied || got.Enforcement != "not_attached" || got.Audit.Result != "recorded_only" {
		t.Fatalf("%+v", got)
	}
	if len(st.ActiveIsolations()) != 0 {
		t.Fatal("a request that was only recorded became active")
	}
}

func TestIsolateIsRefusedWhenItCannotBeEnforced(t *testing.T) {
	st, f := stateWithVM("tap0")
	f.ok, f.why = false, "no management allow list is configured"
	got := st.Isolate("db", "cli")
	if got.Applied || got.Audit.Result != "refused" || !strings.Contains(got.Reason, "allow list") {
		t.Fatalf("%+v", got)
	}
	if len(f.calls) != 0 {
		t.Fatalf("the enforcer was called although it said it was unavailable: %v", f.calls)
	}
	if len(st.ActiveIsolations()) != 0 {
		t.Fatal("a refused request is active")
	}
}

func TestIsolateRefusesWhatItCannotFindOrEnforceOn(t *testing.T) {
	st, f := stateWithVM("tap0")
	if got := st.Isolate("nope", "cli"); got.Applied || got.Audit.Result != "refused" || !strings.Contains(got.Reason, "no VM") {
		t.Fatalf("unknown VM: %+v", got)
	}
	st.SetVMs([]identity.VM{{Name: "slirp", PID: 5}}) // user-mode networking: no tap
	if got := st.Isolate("slirp", "cli"); got.Applied || !strings.Contains(got.Reason, "no tap interface") {
		t.Fatalf("no tap: %+v", got)
	}
	if len(f.calls) != 0 {
		t.Fatalf("enforced on something that could not be: %v", f.calls)
	}
}

func TestAppliedOnlyAfterTheEnforcerSaysSo(t *testing.T) {
	st, f := stateWithVM("tap0", "tap1")
	got := st.Isolate("db", "shukractl")
	if !got.Applied || got.Enforcement != "tcx" || got.Audit.Result != "applied" || len(got.Taps) != 2 {
		t.Fatalf("%+v", got)
	}
	if !f.isolated["tap0"] || !f.isolated["tap1"] {
		t.Fatalf("taps not isolated: %v", f.isolated)
	}
	if !strings.Contains(got.Reason, "10.0.0.1/32") || !strings.Contains(got.Reason, "neighbour discovery") {
		t.Fatalf("the reason must say what is still allowed: %q", got.Reason)
	}
	if a := st.ActiveIsolations(); len(a) != 1 || a[0] != "db" {
		t.Fatalf("%v", a)
	}
	rel := st.Release("db", "shukractl")
	if !rel.Applied || rel.Audit.Action != "release" || f.isolated["tap0"] || f.isolated["tap1"] {
		t.Fatalf("%+v %v", rel, f.isolated)
	}
	if len(st.ActiveIsolations()) != 0 {
		t.Fatal("a released VM is still active")
	}
	if len(st.Isolations()) != 2 {
		t.Fatalf("both actions belong in the audit trail: %d", len(st.Isolations()))
	}
}

func TestPartialIsolationIsReportedAndKept(t *testing.T) {
	st, f := stateWithVM("tap0", "tap1")
	f.failOn["tap1"] = true
	got := st.Isolate("db", "cli")
	if got.Applied || got.Audit.Result != "partial" || !strings.Contains(got.Reason, "1 of 2") || !strings.Contains(got.Reason, "tap1") {
		t.Fatalf("%+v", got)
	}
	// What took effect stays: a half-isolated VM is safer contained than reopened.
	if !f.isolated["tap0"] {
		t.Fatal("the tap that was isolated was rolled back")
	}
	if len(st.ActiveIsolations()) != 1 {
		t.Fatal("a partial isolation must still be re-applied later")
	}
	f.failOn["tap0"], f.failOn["tap1"] = true, true
	got = st.Isolate("db", "cli")
	if got.Applied || got.Audit.Result != "failed" {
		t.Fatalf("%+v", got)
	}
}

func TestReapplyRestoresIsolationAfterARestartAndOnlyForWhatWasApplied(t *testing.T) {
	// A previous run isolated db, tried to isolate web without an allow list, and
	// released cache. Only db should come back.
	old := []Isolation{
		{VM: "db", Applied: true, Audit: Audit{Action: "isolate", VM: "db", Result: "applied"}},
		{VM: "web", Audit: Audit{Action: "isolate", VM: "web", Result: "refused"}},
		{VM: "cache", Applied: true, Audit: Audit{Action: "isolate", VM: "cache", Result: "applied"}},
		{VM: "cache", Applied: true, Audit: Audit{Action: "release", VM: "cache", Result: "applied"}},
	}
	st := New("node-07")
	st.Restore(nil, old, nil)
	st.SetVMs([]identity.VM{
		{Name: "db", Taps: []string{"tapdb"}}, {Name: "web", Taps: []string{"tapweb"}}, {Name: "cache", Taps: []string{"tapcache"}},
	})
	f := newFake()
	st.SetEnforcer(f)

	if acted := st.ReapplyIsolations(); len(acted) != 1 || acted[0] != "db" {
		t.Fatalf("re-applied %v", acted)
	}
	if !f.isolated["tapdb"] || f.isolated["tapweb"] || f.isolated["tapcache"] {
		t.Fatalf("%v", f.isolated)
	}
	before := len(f.calls)
	if acted := st.ReapplyIsolations(); len(acted) != 0 || len(f.calls) != before {
		t.Fatalf("a second pass with nothing pending did work: %v %v", acted, f.calls)
	}
	// A VM that came back with a new tap is contained again on the next pass.
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tapdb2"}}})
	if acted := st.ReapplyIsolations(); len(acted) != 1 || !f.isolated["tapdb2"] {
		t.Fatalf("new tap not isolated: %v %v", acted, f.isolated)
	}
	if n := len(st.Isolations()); n != len(old) {
		t.Fatalf("re-applying must not add to the audit trail: %d", n)
	}
	// When it cannot enforce, it does nothing rather than pretend.
	f2 := newFake()
	f2.ok = false
	st.SetEnforcer(f2)
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tapx"}}})
	if acted := st.ReapplyIsolations(); len(acted) != 0 || len(f2.calls) != 0 {
		t.Fatalf("%v %v", acted, f2.calls)
	}
}

func TestTapsAreJoinedToTheVMThatOwnsThem(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}, {Name: "web", Taps: []string{"tap1"}}})
	if st.Taps("") != nil {
		t.Fatal("rows without a source")
	}
	st.SetTapSource(func() []TapStat {
		return []TapStat{
			{Name: "tap0", FromBytes: 10, Isolated: true},
			{Name: "tap1", ToBytes: 7},
			{Name: "orphan", FromBytes: 999}, // no VM owns it
		}
	})
	all := st.Taps("")
	if len(all) != 2 || all[0].VM != "db" || !all[0].Isolated || all[1].VM != "web" {
		t.Fatalf("%+v", all)
	}
	if one := st.Taps("web"); len(one) != 1 || one[0].ToBytes != 7 {
		t.Fatalf("%+v", one)
	}
}

func TestStatusAndExplainSayWhetherGuestTrafficIsSeen(t *testing.T) {
	st := New("node-07")
	if s := st.Status().Summary; !strings.Contains(s, "not attached") {
		t.Fatalf("%q", s)
	}
	has := func(list []string, sub string) bool {
		for _, l := range list {
			if strings.Contains(l, sub) {
				return true
			}
		}
		return false
	}
	st.SetVMs([]identity.VM{{Name: "db", PID: 1}})
	st.SetCounters(map[uint32]aggregate.Counters{1: {OnCPUNs: 1}})
	if !has(st.Explain("db", timeNow()).Missing, "guest tap attribution") {
		t.Fatal("the tap program is not attached, so it is missing")
	}
	st.SetPrograms([]Program{{Name: "tap", Status: "attached", Detail: "2 taps"}})
	if s := st.Status().Summary; !strings.Contains(s, "guest traffic") || !strings.Contains(s, "2 taps") {
		t.Fatalf("%q", s)
	}
	if has(st.Explain("db", timeNow()).Missing, "guest tap attribution") {
		t.Fatal("it is attached, so it is no longer missing")
	}
	if !has(st.Explain("db", timeNow()).Missing, "in-guest process identity") {
		t.Fatal("what still is missing must stay listed")
	}
}
