package response

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/state"
)

var r0 = time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)

// fakeEnf is an Enforcer that records what it was asked and can be made to fail.
type fakeEnf struct {
	mu       sync.Mutex
	on       bool
	isolated map[string]bool
	calls    []string
}

func (f *fakeEnf) Available() (bool, string) {
	if !f.on {
		return false, "no management allow list is configured (-isolate-allow)"
	}
	return true, ""
}
func (f *fakeEnf) AllowList() []string { return []string{"10.0.0.0/24"} }
func (f *fakeEnf) Isolated(tap string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isolated[tap]
}
func (f *fakeEnf) Durable() bool { return true }
func (f *fakeEnf) Isolate(taps []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range taps {
		f.isolated[t] = true
		f.calls = append(f.calls, "isolate "+t)
	}
	return taps, nil
}
func (f *fakeEnf) Release(taps []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range taps {
		delete(f.isolated, t)
		f.calls = append(f.calls, "release "+t)
	}
	return taps, nil
}

type memStore struct {
	mu      sync.Mutex
	records []state.Action
	bundles map[string][]byte
}

func (m *memStore) Append(a state.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, a)
	return nil
}
func (m *memStore) SaveBundle(id string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bundles == nil {
		m.bundles = map[string][]byte{}
	}
	m.bundles[id] = b
	return nil
}
func (m *memStore) LoadBundle(id string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bundles[id]
	return b, ok
}

type world struct {
	t   *testing.T
	st  *state.State
	enf *fakeEnf
	eng *Engine
	sto *memStore
	now time.Time
}

func newWorld(t *testing.T, yaml string) *world {
	t.Helper()
	w := &world{t: t, st: state.New("node-07"), enf: &fakeEnf{on: true, isolated: map[string]bool{}}, sto: &memStore{}, now: r0}
	w.st.SetVMs([]identity.VM{
		{Name: "web", PID: 100, Taps: []string{"tapweb"}},
		{Name: "db", PID: 200, Taps: []string{"tapdb"}},
	})
	w.st.SetEnforcer(w.enf)
	w.eng = New(w.st, w.sto)
	w.eng.now = func() time.Time { return w.now }
	cfg, err := detect.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	w.eng.SetConfig(cfg)
	return w
}

func (w *world) detect(vm, rule, sev string) {
	w.eng.Handle(event.Event{Kind: event.KindDetection, TS: w.now, Rule: rule, Severity: sev, VM: event.VM{Name: vm}, Message: rule + " on " + vm})
}

func (w *world) advance(d time.Duration) { w.now = w.now.Add(d) }

func (w *world) status(id string) string {
	for _, a := range w.eng.List(true) {
		if a.ID == id {
			return a.Status
		}
	}
	return ""
}

func (w *world) announcements() []event.Event {
	var out []event.Event
	for _, e := range w.st.Events("") {
		if e.Kind == event.KindDetection && strings.HasPrefix(e.Rule, "action-") {
			out = append(out, e)
		}
	}
	return out
}

const proposeCfg = "responses:\n  - {name: contain, action: isolate, rules: [c2]}\n"
const enforceCfg = "responses:\n  - {name: contain, action: isolate, mode: enforce, rules: [c2], release_after: 10m}\n"

func TestAProposalWaitsForAPersonAndNothingIsIsolatedUntilTheyApprove(t *testing.T) {
	w := newWorld(t, proposeCfg)
	w.detect("web", "c2", "high")
	list := w.eng.List(false)
	if len(list) != 1 || list[0].Status != "pending" || list[0].Mode != "propose" || list[0].VM != "web" || list[0].Expires.Sub(w.now) != 30*time.Minute {
		t.Fatalf("%+v", list)
	}
	if len(w.enf.calls) != 0 {
		t.Fatalf("a proposal must not touch the VM: %v", w.enf.calls)
	}
	a, err := w.eng.Approve(list[0].ID, "alice")
	if err != nil || a.Status != "executed" || a.DecidedBy != "alice" {
		t.Fatalf("%+v %v", a, err)
	}
	if len(w.enf.calls) != 1 || w.enf.calls[0] != "isolate tapweb" {
		t.Fatalf("%v", w.enf.calls)
	}
	isos := w.st.Isolations()
	if len(isos) != 1 || !strings.Contains(isos[0].Audit.Actor, "approved by alice") || !strings.Contains(isos[0].Audit.Actor, a.ID) {
		t.Fatalf("the isolation record must say who approved which action: %+v", isos)
	}
	if got := w.eng.List(false); len(got) != 0 {
		t.Fatalf("a decided action is no longer waiting: %+v", got)
	}
}

func TestRejectingLeavesTheVMAloneAndAnApprovedOrRejectedOneCannotBeDecidedAgain(t *testing.T) {
	w := newWorld(t, proposeCfg)
	w.detect("web", "c2", "high")
	a, err := w.eng.Reject("a-1", "bob")
	if err != nil || a.Status != "rejected" || a.DecidedBy != "bob" || len(w.enf.calls) != 0 {
		t.Fatalf("%+v %v %v", a, err, w.enf.calls)
	}
	if _, err := w.eng.Approve("a-1", "alice"); !errors.Is(err, state.ErrActionNotPending) {
		t.Fatalf("a rejected proposal cannot be approved afterwards: %v", err)
	}
	if _, err := w.eng.Reject("a-1", "alice"); !errors.Is(err, state.ErrActionNotPending) {
		t.Fatal(err)
	}
	if _, err := w.eng.Approve("a-99", "alice"); !errors.Is(err, state.ErrActionNotFound) {
		t.Fatal(err)
	}
	if len(w.enf.calls) != 0 {
		t.Fatalf("%v", w.enf.calls)
	}
}

func TestAnUnansweredProposalLapsesAndCanNoLongerBeApproved(t *testing.T) {
	w := newWorld(t, proposeCfg)
	w.detect("web", "c2", "high")
	w.advance(31 * time.Minute)
	w.eng.Tick(w.now)
	if w.status("a-1") != "expired" {
		t.Fatalf("%s", w.status("a-1"))
	}
	if _, err := w.eng.Approve("a-1", "alice"); !errors.Is(err, state.ErrActionNotPending) {
		t.Fatalf("%v", err)
	}
	// An approval that comes in before the tick has noticed still cannot beat the deadline.
	w2 := newWorld(t, proposeCfg)
	w2.detect("web", "c2", "high")
	w2.advance(31 * time.Minute)
	if _, err := w2.eng.Approve("a-1", "alice"); err == nil || !strings.Contains(err.Error(), "expired") || len(w2.enf.calls) != 0 {
		t.Fatalf("%v %v", err, w2.enf.calls)
	}
}

func TestEnforceIsolatesAtOnceAndReleasesItselfWhenItsTimeComes(t *testing.T) {
	w := newWorld(t, enforceCfg)
	w.detect("web", "c2", "high")
	a := w.eng.List(true)[0]
	if a.Status != "executed" || a.DecidedBy != "auto:contain:a-1" || a.ReleaseAt.Sub(w.now) != 10*time.Minute {
		t.Fatalf("%+v", a)
	}
	if len(w.enf.calls) != 1 {
		t.Fatalf("%v", w.enf.calls)
	}
	w.advance(9 * time.Minute)
	w.eng.Tick(w.now)
	if w.status("a-1") != "executed" || !w.enf.isolated["tapweb"] {
		t.Fatal("released early")
	}
	w.advance(2 * time.Minute)
	w.eng.Tick(w.now)
	if w.status("a-1") != "released" || w.enf.isolated["tapweb"] {
		t.Fatalf("%s isolated=%v", w.status("a-1"), w.enf.isolated["tapweb"])
	}
	w.eng.Tick(w.now.Add(time.Hour))
	if n := strings.Count(strings.Join(w.enf.calls, ","), "release"); n != 1 {
		t.Fatalf("released %d times", n)
	}
}

func TestAReleaseTimerSurvivesARestartAndIsNeitherForgottenNorExtended(t *testing.T) {
	w := newWorld(t, enforceCfg)
	w.detect("web", "c2", "high")
	// The daemon restarts: a new engine, the records reloaded, and the clock is past the release time.
	w2 := newWorld(t, enforceCfg)
	w2.enf.isolated["tapweb"] = true // the kernel still holds it (pinned)
	w2.st.Restore(nil, w.st.Isolations(), nil)
	w2.eng.Restore(w.sto.records)
	w2.now = r0.Add(20 * time.Minute)
	w2.eng.Tick(w2.now)
	if w2.status("a-1") != "released" || w2.enf.isolated["tapweb"] {
		t.Fatalf("an isolation that should have ended while the daemon was down ends on the first tick: %s", w2.status("a-1"))
	}
	// And one whose time has not come stays, with the original deadline.
	w3 := newWorld(t, enforceCfg)
	w3.st.Restore(nil, w.st.Isolations(), nil)
	w3.eng.Restore(w.sto.records)
	w3.now = r0.Add(5 * time.Minute)
	w3.eng.Tick(w3.now)
	if a := w3.eng.List(true)[0]; a.Status != "executed" || !a.ReleaseAt.Equal(r0.Add(10*time.Minute)) {
		t.Fatalf("%+v", a)
	}
}

func TestOnlyTheDetectionsAResponseNamesAndOnlyAtItsSeverityAreAnswered(t *testing.T) {
	w := newWorld(t, "responses:\n  - {name: contain, action: isolate, rules: [c2], min_severity: high}\n")
	w.detect("web", "other-rule", "critical")
	w.detect("web", "c2", "medium")
	w.eng.Handle(event.Event{Kind: event.KindDetection, TS: w.now, Rule: "c2", Severity: "high"}) // no VM: nothing to isolate
	if len(w.eng.List(true)) != 0 {
		t.Fatalf("%+v", w.eng.List(true))
	}
	w.detect("web", "c2", "high")
	if len(w.eng.List(true)) != 1 {
		t.Fatal("the named rule at the floor is answered")
	}
}

func TestAProtectedVMIsNeverIsolatedByAnyResponseNotEvenAnApprovedOne(t *testing.T) {
	cfg := "guardrails:\n  never_isolate: [db]\n" + proposeCfg
	w := newWorld(t, cfg)
	w.detect("db", "c2", "critical")
	a := w.eng.List(true)[0]
	if a.Status != "refused" || a.Guardrail != "never_isolate" || len(w.enf.calls) != 0 {
		t.Fatalf("%+v", a)
	}
	// A proposal made before the VM was protected is refused when someone approves it.
	w2 := newWorld(t, proposeCfg)
	w2.detect("db", "c2", "high")
	w2.eng.SetConfig(mustParse(t, cfg))
	if _, err := w2.eng.Approve("a-1", "alice"); err == nil || len(w2.enf.calls) != 0 || w2.status("a-1") != "refused" {
		t.Fatalf("%v %v %s", err, w2.enf.calls, w2.status("a-1"))
	}
}

func mustParse(t *testing.T, y string) *detect.Config {
	c, err := detect.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNothingIsDoneWhenIsolateIsNotAvailableAndTheRefusalSaysWhy(t *testing.T) {
	w := newWorld(t, enforceCfg)
	w.enf.on = false
	w.detect("web", "c2", "high")
	a := w.eng.List(true)[0]
	if a.Status != "refused" || a.Guardrail != "isolate_unavailable" || !strings.Contains(a.Result, "-isolate-allow") || len(w.enf.calls) != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestADryRunSaysWhatWouldHaveBeenDoneAndChangesNothing(t *testing.T) {
	w := newWorld(t, "responses:\n  - {name: contain, action: isolate, mode: enforce, dry_run: true}\n")
	w.detect("web", "whatever", "high")
	a := w.eng.List(true)[0]
	if a.Status != "dry_run" || !a.DryRun || len(w.enf.calls) != 0 || w.enf.isolated["tapweb"] {
		t.Fatalf("%+v %v", a, w.enf.calls)
	}
	if got := w.announcements(); len(got) != 1 || got[0].Rule != "action-dry-run" || !strings.Contains(got[0].Message, "nothing changed") {
		t.Fatalf("%+v", got)
	}
}

func TestOnlySoManyIsolationsMayBeCarriedOutAutomaticallyInAnHour(t *testing.T) {
	cfg := "guardrails:\n  max_per_hour: 2\nresponses:\n  - {name: contain, action: isolate, mode: enforce, rules: [c2], cooldown: 1m}\n"
	w := newWorld(t, cfg)
	w.st.SetVMs([]identity.VM{
		{Name: "v1", PID: 1, Taps: []string{"t1"}}, {Name: "v2", PID: 2, Taps: []string{"t2"}},
		{Name: "v3", PID: 3, Taps: []string{"t3"}}, {Name: "v4", PID: 4, Taps: []string{"t4"}},
	})
	for _, vm := range []string{"v1", "v2", "v3"} {
		w.detect(vm, "c2", "high")
	}
	got := map[string]string{}
	for _, a := range w.eng.List(true) {
		got[a.VM] = a.Status + "/" + a.Guardrail
	}
	if got["v1"] != "executed/" || got["v2"] != "executed/" || got["v3"] != "refused/max_per_hour" {
		t.Fatalf("%v", got)
	}
	if w.enf.isolated["t3"] {
		t.Fatal("the third was isolated past the cap")
	}
	w.advance(61 * time.Minute)
	w.detect("v4", "c2", "high")
	if a := w.eng.List(true)[0]; a.VM != "v4" || a.Status != "executed" {
		t.Fatalf("the cap is a rolling hour: %+v", a)
	}
}

func TestAPersonsApprovalIsNotCountedAgainstTheAutomaticCap(t *testing.T) {
	cfg := "guardrails:\n  max_per_hour: 1\nresponses:\n  - {name: ask, action: isolate, rules: [c2]}\n  - {name: auto, action: isolate, mode: enforce, rules: [c3]}\n"
	w := newWorld(t, cfg)
	w.detect("web", "c2", "high")
	if _, err := w.eng.Approve("a-1", "alice"); err != nil {
		t.Fatal(err)
	}
	w.detect("db", "c3", "high")
	if a := w.eng.List(true)[0]; a.Status != "executed" {
		t.Fatalf("a human's decision is not the automatic cap's business: %+v", a)
	}
}

func TestAVMIsLeftAloneForTheCooldownAndWhileAProposalIsWaitingOrItIsAlreadyIsolated(t *testing.T) {
	w := newWorld(t, "responses:\n  - {name: ask, action: isolate, rules: [c2], cooldown: 10m}\n")
	w.detect("web", "c2", "high")
	w.detect("web", "c2", "high") // a proposal is already waiting
	if len(w.eng.List(true)) != 1 {
		t.Fatalf("%d", len(w.eng.List(true)))
	}
	if _, err := w.eng.Reject("a-1", "bob"); err != nil {
		t.Fatal(err)
	}
	w.advance(5 * time.Minute)
	w.detect("web", "c2", "high") // inside the cooldown
	if len(w.eng.List(true)) != 1 {
		t.Fatal("acted again inside the cooldown")
	}
	w.advance(6 * time.Minute)
	w.detect("web", "c2", "high")
	if len(w.eng.List(true)) != 2 {
		t.Fatal("the cooldown is over")
	}
	// A VM that is already isolated is not isolated twice, and no record is made of a non-decision.
	w.eng.Approve("a-2", "alice")
	before := len(w.eng.List(true))
	w.advance(time.Hour)
	w.detect("web", "c2", "high")
	if len(w.eng.List(true)) != before || len(w.enf.calls) != 1 {
		t.Fatalf("%d actions, calls %v", len(w.eng.List(true)), w.enf.calls)
	}
}

func TestEveryDecisionIsAnnouncedAsADetectionAndAResponseNeverAnswersItsOwnAnnouncements(t *testing.T) {
	w := newWorld(t, "responses:\n  - {name: any, action: isolate, min_severity: low}\n")
	w.detect("web", "c2", "high")
	if got := w.announcements(); len(got) != 1 || got[0].Rule != "action-proposed" || !strings.Contains(got[0].Message, "shukractl approve a-1") || got[0].VM.Name != "web" {
		t.Fatalf("the announcement is how a person hears that a decision is waiting: %+v", got)
	}
	// Feed the announcement back, as the event hook would, with nothing else in the way (no proposal waiting, the
	// cooldown over): a response must still not answer its own announcement.
	if _, err := w.eng.Reject("a-1", "bob"); err != nil {
		t.Fatal(err)
	}
	w.advance(3 * time.Hour)
	announced := w.announcements()[0]
	w.eng.Handle(announced)
	if len(w.eng.List(true)) != 1 {
		t.Fatalf("a response answered its own announcement: %d", len(w.eng.List(true)))
	}
	w.detect("web", "c2", "high") // a real detection is answered again
	w.eng.Approve("a-2", "alice")
	rules := []string{}
	for _, e := range w.announcements() {
		rules = append(rules, e.Rule)
	}
	if strings.Join(rules, ",") != "action-proposed,action-rejected,action-proposed,action-executed" {
		t.Fatalf("%v", rules)
	}
}

func TestEveryActionKeepsTheEvidenceItWasMadeOnAndTheStoreHasIt(t *testing.T) {
	w := newWorld(t, proposeCfg)
	w.detect("web", "c2", "high")
	b, ok := w.eng.Bundle("a-1")
	if !ok || !strings.Contains(string(b), `"vm": "web"`) || !strings.Contains(string(b), `"product": "shukra"`) {
		t.Fatalf("%v %s", ok, b)
	}
	if _, ok := w.sto.LoadBundle("a-1"); !ok {
		t.Fatal("not persisted")
	}
	if len(w.sto.records) == 0 || w.sto.records[0].ID != "a-1" {
		t.Fatalf("%+v", w.sto.records)
	}
	// After a restart the bundle comes from the store.
	fresh := New(w.st, w.sto)
	if _, ok := fresh.Bundle("a-1"); !ok {
		t.Fatal("the evidence is gone after a restart")
	}
	if _, ok := fresh.Bundle("a-77"); ok {
		t.Fatal("a bundle that never existed")
	}
}

func TestRestoreTakesTheLastRecordOfEachActionAndKeepsNumberingAfterThem(t *testing.T) {
	w := newWorld(t, proposeCfg)
	w.eng.Restore([]state.Action{
		{ID: "a-1", VM: "web", Response: "contain", Status: "pending", Created: r0},
		{ID: "a-2", VM: "db", Response: "contain", Status: "pending", Created: r0},
		{ID: "a-1", VM: "web", Response: "contain", Status: "rejected", Created: r0},
	})
	if w.status("a-1") != "rejected" || w.status("a-2") != "pending" || len(w.eng.List(true)) != 2 {
		t.Fatalf("%+v", w.eng.List(true))
	}
	w.now = r0.Add(time.Hour)
	w.detect("web", "c2", "high")
	if got := w.eng.List(true); got[0].ID != "a-3" {
		t.Fatalf("ids must not be reused: %+v", got)
	}
	if c := w.eng.Counts(); c["rejected"] != 1 || c["pending"] != 2 {
		t.Fatalf("%v", c)
	}
}

func TestTheQueueNeverBlocksTheEventPathAndDropsAreCounted(t *testing.T) {
	w := newWorld(t, proposeCfg)
	for i := 0; i < queueSize+10; i++ {
		w.eng.OnDetection(event.Event{Kind: event.KindDetection, Rule: "c2", Severity: "high", VM: event.VM{Name: "web"}})
	}
	if w.eng.Dropped() != 10 {
		t.Fatalf("%d dropped", w.eng.Dropped())
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { w.eng.Run(stop); close(done) }()
	deadline := time.After(5 * time.Second)
	for len(w.eng.List(true)) == 0 {
		select {
		case <-deadline:
			t.Fatal("the worker did not answer the queued detections")
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(stop)
	<-done
	if len(w.eng.List(true)) != 1 {
		t.Fatalf("all of them are one VM and one proposal: %d", len(w.eng.List(true)))
	}
}
