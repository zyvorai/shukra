package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/state"
)

func TestWhatWasDecidedSurvivesARestartAndTheFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	a, past, err := OpenActions(dir)
	if err != nil || len(past) != 0 {
		t.Fatalf("%v %v", past, err)
	}
	now := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	_ = a.Append(state.Action{ID: "a-1", VM: "web", Status: "pending", Created: now})
	_ = a.Append(state.Action{ID: "a-1", VM: "web", Status: "executed", Created: now, ReleaseAt: now.Add(time.Hour)})
	if err := a.SaveBundle("a-1", []byte(`{"vm":"web"}`)); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b, past, err := OpenActions(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(past) != 2 || past[1].Status != "executed" || !past[1].ReleaseAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("%+v", past)
	}
	if got, ok := b.LoadBundle("a-1"); !ok || string(got) != `{"vm":"web"}` {
		t.Fatalf("%q %v", got, ok)
	}
	for _, p := range []string{filepath.Join(dir, actionsFile), filepath.Join(dir, incidentDir, "a-1.json")} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, incidentDir)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("the directory of bundles must be private: %v", fi.Mode())
	}
}

func TestAnIdFromAURLCannotNameAPath(t *testing.T) {
	a, _, err := OpenActions(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	outside := filepath.Join(filepath.Dir(a.dir), "secret.json")
	_ = os.WriteFile(outside, []byte("secret"), 0o600)
	for _, id := range []string{"../secret", "../../etc/passwd", "a-1/../../x", "a-", "a-abc", "", "a-1234567890", "A-1", "a-1.json"} {
		if _, ok := a.LoadBundle(id); ok {
			t.Errorf("%q was read", id)
		}
		if err := a.SaveBundle(id, []byte("x")); err == nil {
			t.Errorf("%q was written", id)
		}
	}
	if _, err := os.Stat(filepath.Join(a.dir, "a-1.json")); err == nil {
		t.Fatal("wrote outside the bundle directory")
	}
}

func TestOnlyTheNewestBundlesAreKept(t *testing.T) {
	a, _, err := OpenActions(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for i := 1; i <= maxIncidents+25; i++ {
		if err := a.SaveBundle(fmt.Sprintf("a-%d", i), []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(a.dir, incidentDir))
	if len(entries) != maxIncidents {
		t.Fatalf("%d bundles on disk", len(entries))
	}
	if _, ok := a.LoadBundle("a-1"); ok {
		t.Fatal("the oldest should have gone")
	}
	if _, ok := a.LoadBundle(fmt.Sprintf("a-%d", maxIncidents+25)); !ok {
		t.Fatal("the newest was lost")
	}
	// Numeric, not alphabetical: a-9 is older than a-10.
	if _, ok := a.LoadBundle("a-26"); !ok {
		t.Fatal("ordering by name would have dropped a-26 before a-3")
	}
}
