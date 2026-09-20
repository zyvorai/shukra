package baseline

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)

func opts() Options {
	return Options{Learn: time.Hour, MaxItems: 5, MaxAge: 24 * time.Hour, MaxAlertsPerDay: 3}
}

func TestEverythingIsOnlyRecordedWhileALearningPeriodRuns(t *testing.T) {
	s := NewStore(opts())
	for i := 0; i < 4; i++ {
		if r := s.Observe("web", Destination, fmt.Sprintf("10.0.%d.0/24", i), t0.Add(time.Duration(i)*10*time.Minute)); r.Verdict != Learning {
			t.Fatalf("observation %d: %v", i, r.Verdict)
		}
	}
	// Seeing one again is known, even inside the period.
	if r := s.Observe("web", Destination, "10.0.0.0/24", t0.Add(35*time.Minute)); r.Verdict != Known {
		t.Fatalf("%v", r.Verdict)
	}
}

func TestTheFirstSightingAfterLearningIsNewOnceAndThenKnown(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "10.0.0.0/24", t0)
	after := t0.Add(2 * time.Hour)
	if r := s.Observe("web", Destination, "203.0.113.0/24", after); r.Verdict != New {
		t.Fatalf("a network never seen, after learning: %v", r.Verdict)
	}
	if r := s.Observe("web", Destination, "203.0.113.0/24", after.Add(time.Second)); r.Verdict != Known {
		t.Fatalf("it must alert once: %v", r.Verdict)
	}
	if r := s.Observe("web", Destination, "10.0.0.0/24", after); r.Verdict != Known {
		t.Fatalf("what was learned stays known: %v", r.Verdict)
	}
}

func TestEachKindIsItsOwnSetAndEachVMItsOwnBaseline(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "x", t0)
	s.Observe("web", DNSSuffix, "example.com", t0)
	s.Observe("db", Destination, "y", t0)
	after := t0.Add(2 * time.Hour)
	if s.Observe("web", InboundPeer, "x", after).Verdict != New {
		t.Fatal("the same text under another kind is a different thing")
	}
	if s.Observe("db", Destination, "x", after).Verdict != New {
		t.Fatal("what web learned says nothing about db")
	}
	if s.Observe("web", Destination, "x", after).Verdict != Known {
		t.Fatal("web's own is known")
	}
}

func TestAVMFirstSeenLateHasItsOwnLearningPeriod(t *testing.T) {
	s := NewStore(opts())
	s.Observe("old", Destination, "a", t0)
	late := t0.Add(5 * time.Hour)
	if r := s.Observe("newcomer", Destination, "b", late); r.Verdict != Learning {
		t.Fatalf("a VM first seen now must not alert for its first hour: %v", r.Verdict)
	}
	if r := s.Observe("newcomer", Destination, "c", late.Add(30*time.Minute)); r.Verdict != Learning {
		t.Fatalf("%v", r.Verdict)
	}
	if r := s.Observe("newcomer", Destination, "d", late.Add(90*time.Minute)); r.Verdict != New {
		t.Fatalf("%v", r.Verdict)
	}
}

func TestAnEmptyItemOrVMIsNotLearned(t *testing.T) {
	s := NewStore(opts())
	if r := s.Observe("web", Destination, "", t0); r.Verdict != Known {
		t.Fatal("an empty item is not a thing")
	}
	if r := s.Observe("", Destination, "x", t0); r.Verdict != Known {
		t.Fatal("an unattributed observation is not a VM's")
	}
	if len(s.Status("", t0)) != 0 {
		t.Fatal("neither created a baseline")
	}
}

func TestADailyCapHoldsBackAlertsAndSaysWhenItIsReachedOnce(t *testing.T) {
	s := NewStore(opts()) // 3 a day
	s.Observe("web", Destination, "seed", t0)
	now := t0.Add(2 * time.Hour)
	var verdicts []Verdict
	var capHits int
	for i := 0; i < 6; i++ {
		r := s.Observe("web", Destination, fmt.Sprintf("n%d", i), now.Add(time.Duration(i)*time.Second))
		verdicts = append(verdicts, r.Verdict)
		if r.CapReached {
			capHits++
		}
	}
	if !reflect.DeepEqual(verdicts, []Verdict{New, New, New, Capped, Capped, Capped}) || capHits != 1 {
		t.Fatalf("%v cap reached %d times", verdicts, capHits)
	}
	// Held-back items are still learned, so they are not new tomorrow.
	if s.Observe("web", Destination, "n5", now.Add(time.Minute)).Verdict != Known {
		t.Fatal("a capped item was not recorded")
	}
	// The count starts again after a day.
	if r := s.Observe("web", Destination, "fresh", now.Add(25*time.Hour)); r.Verdict != New {
		t.Fatalf("%v", r.Verdict)
	}
	st := s.Status("web", now.Add(25*time.Hour))[0]
	if st.Suppressed != 3 || st.Alerts != 4 || st.AlertsDay != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestASetIsBoundedAndTheOldestIsTheOneDropped(t *testing.T) {
	s := NewStore(opts()) // 5 per kind
	for i := 0; i < 9; i++ {
		s.Observe("web", Destination, fmt.Sprintf("n%d", i), t0.Add(time.Duration(i)*time.Second))
	}
	items := s.Items("web", 0)
	if len(items) != 5 {
		t.Fatalf("%d items: a guest must not be able to grow a VM's baseline", len(items))
	}
	got := map[string]bool{}
	for _, it := range items {
		got[it.Item] = true
	}
	for _, want := range []string{"n4", "n5", "n6", "n7", "n8"} {
		if !got[want] {
			t.Fatalf("the newest five must stay: %v", got)
		}
	}
	// Re-seeing an old item keeps it: recency, not age of first sight, decides.
	s.Observe("web", Destination, "n4", t0.Add(time.Hour+30*time.Minute))
	s.Observe("web", Destination, "n9", t0.Add(2*time.Hour))
	if !containsItem(s.Items("web", 0), "n4") {
		t.Fatal("an item seen recently was dropped")
	}
	if containsItem(s.Items("web", 0), "n5") {
		t.Fatal("the item unseen for longest should have gone")
	}
}

func containsItem(items []Learned, item string) bool {
	for _, i := range items {
		if i.Item == item {
			return true
		}
	}
	return false
}

func TestAnItemNotSeenForMaxAgeIsNewAgain(t *testing.T) {
	s := NewStore(opts()) // 24 h
	s.Observe("web", DNSSuffix, "example.com", t0)
	if r := s.Observe("web", DNSSuffix, "example.com", t0.Add(23*time.Hour)); r.Verdict != Known {
		t.Fatal(r.Verdict)
	}
	if r := s.Observe("web", DNSSuffix, "example.com", t0.Add(23*time.Hour+25*time.Hour)); r.Verdict != New {
		t.Fatalf("a name unseen for longer than MaxAge comes back as new: %v", r.Verdict)
	}
	// Prune drops only what has expired.
	s.Observe("web", DNSSuffix, "old.test", t0.Add(50*time.Hour))
	if n := s.Prune(t0.Add(50*time.Hour + 30*time.Hour)); n != 2 {
		t.Fatalf("pruned %d", n)
	}
}

func TestForgettingAVMStartsItsLearningOver(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "a", t0)
	if !s.Forget("web") || s.Forget("web") || s.Forget("nobody") {
		t.Fatal("Forget says whether the VM was known")
	}
	late := t0.Add(5 * time.Hour)
	if r := s.Observe("web", Destination, "b", late); r.Verdict != Learning {
		t.Fatalf("after forgetting, a fresh learning period: %v", r.Verdict)
	}
}

func TestStatusListsEveryKindAndSaysWhenLearningEnds(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "a", t0)
	s.Observe("web", Destination, "b", t0)
	s.Observe("web", InboundPeer, "p", t0)
	st := s.Status("web", t0.Add(10*time.Minute))
	if len(st) != 1 || !st[0].Learning || !st[0].LearnUntil.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%+v", st)
	}
	want := []KindCount{{Destination, 2}, {DNSSuffix, 0}, {InboundPeer, 1}}
	if !reflect.DeepEqual(st[0].Counts, want) {
		t.Fatalf("every kind is listed, zero included: %+v", st[0].Counts)
	}
	if st := s.Status("web", t0.Add(2*time.Hour)); st[0].Learning {
		t.Fatal("learning is over")
	}
	if got := s.Status("nobody", t0); got == nil || len(got) != 0 {
		t.Fatalf("an unknown VM is [] and not nil: %#v", got)
	}
}

func TestItemsAreMostRecentFirstAndNilForAnUnknownVM(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "old", t0)
	s.Observe("web", DNSSuffix, "mid.test", t0.Add(time.Minute))
	s.Observe("web", Destination, "new", t0.Add(2*time.Minute))
	items := s.Items("web", 2)
	if len(items) != 2 || items[0].Item != "new" || items[1].Item != "mid.test" {
		t.Fatalf("%+v", items)
	}
	if s.Items("nobody", 0) != nil {
		t.Fatal("an unknown VM has no items, not an empty list")
	}
}

func TestASnapshotRestoresExactlyAndIsOnlyTakenWhenSomethingChanged(t *testing.T) {
	s := NewStore(opts())
	if _, ok := s.Snapshot(); ok {
		t.Fatal("nothing to save")
	}
	s.Observe("web", Destination, "a", t0)
	s.Observe("web", DNSSuffix, "example.com", t0.Add(time.Minute))
	d, ok := s.Snapshot()
	if !ok {
		t.Fatal("something changed")
	}
	if _, ok := s.Snapshot(); ok {
		t.Fatal("a second snapshot with no change should be skipped")
	}
	// A snapshot must not share memory with the live store.
	s.Observe("web", Destination, "later", t0.Add(2*time.Minute))
	if len(d.VMs["web"].Sets[Destination]) != 1 {
		t.Fatal("the snapshot changed after it was taken")
	}
	r := NewStore(opts())
	r.Restore(d)
	if !reflect.DeepEqual(r.Items("web", 0), []Learned{
		{Kind: DNSSuffix, Item: "example.com", First: t0.Add(time.Minute), Last: t0.Add(time.Minute)},
		{Kind: Destination, Item: "a", First: t0, Last: t0},
	}) {
		t.Fatalf("%+v", r.Items("web", 0))
	}
	// A restored VM keeps its learning start, so a restart does not begin learning again.
	if r.Observe("web", Destination, "new", t0.Add(2*time.Hour)).Verdict != New {
		t.Fatal("learning restarted after a restore")
	}
	// Data from a version this build does not know is ignored, not misread.
	bad := NewStore(opts())
	bad.Restore(Data{Version: 2, VMs: d.VMs})
	if len(bad.Status("", t0)) != 0 {
		t.Fatal("an unknown version was loaded")
	}
}

func TestSetOptionsChangesTheLimitsWithoutLosingWhatWasLearned(t *testing.T) {
	s := NewStore(opts())
	s.Observe("web", Destination, "a", t0)
	s.SetOptions(Options{Learn: 10 * time.Minute, MaxAlertsPerDay: 1})
	if got := s.Options(); got.Learn != 10*time.Minute || got.MaxAlertsPerDay != 1 || got.MaxItems != DefaultOptions().MaxItems {
		t.Fatalf("zero fields fall back to the defaults: %+v", got)
	}
	if s.Observe("web", Destination, "a", t0.Add(time.Hour)).Verdict != Known {
		t.Fatal("what was learned is kept")
	}
}
