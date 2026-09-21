package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
)

// viewOf is a BaselineView over a real store, with the two facts the agent would supply.
type viewOf struct {
	s                  *baseline.Store
	enabled, persisted bool
}

func (v viewOf) Enabled() bool             { return v.enabled }
func (v viewOf) Persisted() bool           { return v.persisted }
func (v viewOf) Options() baseline.Options { return v.s.Options() }
func (v viewOf) Status(vm string, now time.Time) []baseline.VMStatus {
	return v.s.Status(vm, now)
}
func (v viewOf) Items(vm string, limit int) []baseline.Learned { return v.s.Items(vm, limit) }
func (v viewOf) Forget(vm string) bool                         { return v.s.Forget(vm) }

func TestDoctorSaysNothingAboutBaselinesUnlessTheyAreOn(t *testing.T) {
	st := healthy(t)
	if byID(st.Doctor(), "baselines") != nil {
		t.Fatal("a check for something that is off is noise")
	}
	st.SetBaselines(viewOf{s: baseline.NewStore(baseline.DefaultOptions()), enabled: false, persisted: true})
	if byID(st.Doctor(), "baselines") != nil {
		t.Fatal("a store with the section absent is off")
	}
}

func TestDoctorWarnsThatBaselinesWithoutADataDirectoryNeverFinishLearning(t *testing.T) {
	st := healthy(t)
	st.SetBaselines(viewOf{s: baseline.NewStore(baseline.DefaultOptions()), enabled: true, persisted: false})
	c := byID(st.Doctor(), "baselines")
	if c == nil || c.Status != "warn" || !strings.Contains(c.Detail, "24h0m0s") || !strings.Contains(c.Fix, "-data-dir") {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorSaysHowManyVMsAreStillLearningAndWhenTheLastEnds(t *testing.T) {
	st := healthy(t)
	store := baseline.NewStore(baseline.Options{Learn: 24 * time.Hour})
	now := time.Now()
	store.Observe("a", baseline.Destination, "x", now.Add(-2*time.Hour))
	store.Observe("b", baseline.Destination, "x", now.Add(-30*time.Hour)) // done
	store.Observe("c", baseline.Destination, "x", now.Add(-1*time.Hour))
	st.SetBaselines(viewOf{s: store, enabled: true, persisted: true})
	c := byID(st.Doctor(), "baselines")
	if c == nil || c.Status != "info" || !strings.HasPrefix(c.Title, "2 of 3 VMs are still learning") {
		t.Fatalf("%+v", c)
	}
	want := now.Add(-1 * time.Hour).Add(24 * time.Hour).UTC().Format("2006-01-02T15:04")
	if !strings.Contains(c.Detail, want) {
		t.Fatalf("the latest end is %s: %s", want, c.Detail)
	}
	done := baseline.NewStore(baseline.Options{Learn: time.Hour})
	done.Observe("a", baseline.Destination, "x", now.Add(-5*time.Hour))
	st.SetBaselines(viewOf{s: done, enabled: true, persisted: true})
	if c := byID(st.Doctor(), "baselines"); c == nil || c.Status != "ok" || !strings.Contains(c.Title, "reporting what is new for 1 VMs") {
		t.Fatalf("%+v", c)
	}
}

// actionsOf is an ActionsView with fixed answers.
type actionsOf struct {
	enabled               bool
	counts                map[string]int
	propose, enforce, dry int
}

func (a actionsOf) Enabled() bool                          { return a.enabled }
func (a actionsOf) List(bool) []Action                     { return nil }
func (a actionsOf) Approve(string, string) (Action, error) { return Action{}, nil }
func (a actionsOf) Reject(string, string) (Action, error)  { return Action{}, nil }
func (a actionsOf) Bundle(string) ([]byte, bool)           { return nil, false }
func (a actionsOf) Counts() map[string]int                 { return a.counts }
func (a actionsOf) Modes() (propose, enforce, dryRun int)  { return a.propose, a.enforce, a.dry }

type enforcerStub struct{ ok bool }

func (e enforcerStub) Available() (bool, string) {
	if e.ok {
		return true, ""
	}
	return false, "no management allow list is configured (-isolate-allow)"
}
func (enforcerStub) AllowList() []string                  { return []string{"10.0.0.0/24"} }
func (enforcerStub) Isolated(string) bool                 { return false }
func (enforcerStub) Durable() bool                        { return true }
func (enforcerStub) Hook() string                         { return "tcx" }
func (enforcerStub) Isolate(t []string) ([]string, error) { return t, nil }
func (enforcerStub) Release(t []string) ([]string, error) { return t, nil }

func TestDoctorSaysNothingAboutResponsesUnlessTheyAreConfigured(t *testing.T) {
	st := healthy(t)
	if byID(st.Doctor(), "responses") != nil {
		t.Fatal("noise")
	}
	st.SetActions(actionsOf{enabled: false})
	if byID(st.Doctor(), "responses") != nil {
		t.Fatal("a view with no responses is off")
	}
}

func TestDoctorWarnsThatResponsesCannotActWithoutIsolateAndOfferedDryRunsAreFine(t *testing.T) {
	st := healthy(t)
	st.SetEnforcer(enforcerStub{ok: false})
	st.SetActions(actionsOf{enabled: true, propose: 1, counts: map[string]int{}})
	c := byID(st.Doctor(), "responses")
	if c == nil || c.Status != "warn" || !strings.Contains(c.Title, "isolate is not enabled") || !strings.Contains(c.Fix, "-isolate-allow") || !strings.Contains(c.Detail, "1 propose, 0 enforce, 0 dry run") {
		t.Fatalf("%+v", c)
	}
	st.SetActions(actionsOf{enabled: true, dry: 2, counts: map[string]int{}})
	if c := byID(st.Doctor(), "responses"); c == nil || c.Status != "ok" {
		t.Fatalf("a dry run needs no isolate: %+v", c)
	}
}

func TestDoctorSaysHowManyProposalsAreWaitingAndOtherwiseThatAllIsWell(t *testing.T) {
	st := healthy(t)
	st.SetEnforcer(enforcerStub{ok: true})
	st.SetActions(actionsOf{enabled: true, propose: 2, enforce: 1, counts: map[string]int{"pending": 3}})
	c := byID(st.Doctor(), "responses")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "3 proposed isolations are waiting") || !strings.Contains(c.Fix, "shukractl actions") {
		t.Fatalf("%+v", c)
	}
	st.SetActions(actionsOf{enabled: true, propose: 2, enforce: 1, counts: map[string]int{"pending": 1}})
	if c := byID(st.Doctor(), "responses"); c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "1 proposed isolations are waiting") {
		t.Fatalf("one waiting proposal is one too many to ignore: %+v", c)
	}
	st.SetActions(actionsOf{enabled: true, propose: 2, enforce: 1, counts: map[string]int{"executed": 4}})
	if c := byID(st.Doctor(), "responses"); c == nil || c.Status != "ok" || !strings.Contains(c.Title, "2 propose, 1 enforce, 0 dry run") {
		t.Fatalf("%+v", c)
	}
}
