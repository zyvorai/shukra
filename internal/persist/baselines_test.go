package persist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
)

func TestWhatWasLearnedSurvivesARestartAndSoDoesTheLearningStart(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	a := baseline.NewStore(baseline.Options{Learn: time.Hour})
	a.Observe("web", baseline.Destination, "203.0.113.0/24", t0)
	a.Observe("web", baseline.DNSSuffix, "example.com", t0.Add(time.Minute))
	if err := SaveBaselines(dir, a); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, baselinesFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file lists what each VM talks to and must be private: %v %v", fi, err)
	}
	b := baseline.NewStore(baseline.Options{Learn: time.Hour})
	LoadBaselines(dir, b)
	if len(b.Items("web", 0)) != 2 {
		t.Fatalf("%+v", b.Items("web", 0))
	}
	// A restart must not begin a new learning period: an item first seen well after the original one is new.
	if r := b.Observe("web", baseline.Destination, "198.51.100.0/24", t0.Add(2*time.Hour)); r.Verdict != baseline.New {
		t.Fatalf("learning started over: %v", r.Verdict)
	}
}

func TestNothingIsWrittenWhenNothingChangedAndAMissingOrDamagedFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	s := baseline.NewStore(baseline.DefaultOptions())
	if err := SaveBaselines(dir, s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, baselinesFile)); err == nil {
		t.Fatal("wrote a file for an empty store")
	}
	s.Observe("web", baseline.Destination, "x", time.Now())
	_ = SaveBaselines(dir, s)
	fi1, _ := os.Stat(filepath.Join(dir, baselinesFile))
	time.Sleep(20 * time.Millisecond)
	_ = SaveBaselines(dir, s) // unchanged
	fi2, _ := os.Stat(filepath.Join(dir, baselinesFile))
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("rewrote an unchanged file")
	}
	// A file that does not parse costs the learning, never the daemon.
	if err := os.WriteFile(filepath.Join(dir, baselinesFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := baseline.NewStore(baseline.DefaultOptions())
	LoadBaselines(dir, fresh)
	if len(fresh.Status("", time.Now())) != 0 {
		t.Fatal("loaded from a damaged file")
	}
	LoadBaselines(t.TempDir(), fresh) // nothing there at all: a first run
}
