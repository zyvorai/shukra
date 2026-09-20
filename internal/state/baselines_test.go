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
