package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

type rec struct {
	N int `json:"n"`
}

func TestLogAppendAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl")
	l, err := OpenLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := l.Append(rec{i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTail[rec](path, 3)
	if err != nil || len(got) != 3 || got[0].N != 3 || got[2].N != 5 {
		t.Fatalf("%v %v", got, err)
	}
	if err := l.Append(rec{6}); err == nil {
		t.Fatal("append after close succeeded")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestLogRotatesAndTailSpansBothFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl")
	l, err := OpenLog(path, 40) // a few records per file
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 1; i <= 12; i++ {
		if err := l.Append(rec{i}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no rolled file: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Size() > 40 {
		t.Fatalf("live file %d bytes, over the cap", fi.Size())
	}
	got, _ := ReadTail[rec](path, 100)
	if len(got) == 0 || got[len(got)-1].N != 12 {
		t.Fatalf("newest record missing: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i].N != got[i-1].N+1 {
			t.Fatalf("records out of order or gapped: %v", got)
		}
	}
}

func TestTornLastLineIsSkippedAndNextRecordIsClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.WriteFile(path, []byte("{\"n\":1}\n{\"n\":2}\n{\"n\":3"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLog(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(rec{4}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	got, _ := ReadTail[rec](path, 10)
	want := []int{1, 2, 4}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, w := range want {
		if got[i].N != w {
			t.Fatalf("%v, want %v", got, want)
		}
	}
}

func TestReadJSONMissingIsZero(t *testing.T) {
	got, err := ReadJSON[[]rec](filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || got != nil {
		t.Fatalf("%v %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "a.json")
	if err := WriteJSON(path, []rec{{1}, {2}}); err != nil {
		t.Fatal(err)
	}
	if got, err = ReadJSON[[]rec](path); err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
}

func TestAttachSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data") // Attach creates it
	st := state.New("node-07")
	h, err := Attach(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	now := time.Now().UTC()
	vm := event.VM{Name: "db"}
	st.AddEvent(event.Event{Kind: event.KindTCPConnect, TS: now, VM: vm, PID: 1, Dst: "1.1.1.1"})
	st.AddEvent(event.Event{Kind: event.KindDetection, TS: now, VM: vm, PID: 1, Severity: "high", Message: "bad dst"})
	st.Isolate("db", "shukractl")
	before := st.Seq()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	st2 := state.New("node-07")
	h2, err := Attach(st2, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if got := st2.Detections("db"); len(got) != 1 || got[0].Message != "bad dst" || got[0].GuestAttributed {
		t.Fatalf("detections %+v", got)
	}
	if got := st2.Isolations(); len(got) != 1 || got[0].VM != "db" || got[0].Applied {
		t.Fatalf("isolations %+v", got)
	}
	if got := st2.Recorder("db", time.Minute, now.Add(time.Second)); len(got) != 2 {
		t.Fatalf("recorder %+v", got)
	}
	if st2.Seq() != before {
		t.Fatalf("seq %d, want %d so a client cursor stays valid", st2.Seq(), before)
	}
	st2.AddEvent(event.Event{Kind: event.KindExec, PID: 2})
	if evs := st2.EventsSince("", before); len(evs) != 1 || evs[0].Seq != before+1 {
		t.Fatalf("new event reused a seq: %+v", evs)
	}

	// Restored records must not be written again on the way in.
	h2.Close()
	if got, _ := ReadTail[event.Event](filepath.Join(dir, detectionsFile), 100); len(got) != 1 {
		t.Fatalf("detections file has %d records after a restore, want 1", len(got))
	}
}

func TestAttachDoesNotTrustAttributionInFiles(t *testing.T) {
	dir := t.TempDir()
	line := `{"seq":9,"kind":"detection","vm":{"name":"db"},"guest_attributed":true,"attribution":"guest","message":"x"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, detectionsFile), []byte(line+"not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := state.New("node-07")
	h, err := Attach(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	got := st.Detections("")
	if len(got) != 1 || got[0].GuestAttributed || got[0].Attribution != event.AttributionQEMU || got[0].Product != "shukra" {
		t.Fatalf("%+v", got)
	}
	if st.Seq() != 9 {
		t.Fatalf("seq %d", st.Seq())
	}
}

func TestAttachRefusesUnusableDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Attach(state.New("n"), filepath.Join(f, "sub")); err == nil || strings.Contains(err.Error(), "restored") {
		t.Fatalf("err %v", err)
	}
}

func TestReleaseAllRecordsAReleaseSoTheNextStartDoesNotReIsolate(t *testing.T) {
	dir := t.TempDir()
	st := state.New("node-07")
	h, err := Attach(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	// db was isolated and stays so. cache was isolated then released. web was refused.
	// mail was only partly isolated, which still counts as contained.
	st.Restore(nil, nil, nil)
	for _, iso := range []state.Isolation{
		{VM: "db", Applied: true, Audit: state.Audit{Action: "isolate", VM: "db", Result: "applied"}},
		{VM: "cache", Applied: true, Audit: state.Audit{Action: "isolate", VM: "cache", Result: "applied"}},
		{VM: "cache", Applied: true, Audit: state.Audit{Action: "release", VM: "cache", Result: "applied"}},
		{VM: "web", Audit: state.Audit{Action: "isolate", VM: "web", Result: "refused"}},
		{VM: "mail", Audit: state.Audit{Action: "isolate", VM: "mail", Result: "partial"}},
	} {
		h.Isolation(iso)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := RecordReleaseAll(dir, "shukrad -detach-all")
	if err != nil || n != 2 {
		t.Fatalf("released %d (want db and mail): %v", n, err)
	}
	// A restarted daemon reads the trail back. Nothing is active, so nothing is re-applied.
	st2 := state.New("node-07")
	h2, err := Attach(st2, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if a := st2.ActiveIsolations(); len(a) != 0 {
		t.Fatalf("still active after detach-all: %v", a)
	}
	var lifted int
	for _, iso := range st2.Isolations() {
		if iso.Audit.Actor == "shukrad -detach-all" {
			lifted++
			if iso.Audit.Action != "release" || !iso.Applied {
				t.Fatalf("%+v", iso)
			}
		}
	}
	if lifted != 2 {
		t.Fatalf("%d release records in the trail", lifted)
	}
	// Running it again has nothing left to release, and records nothing.
	if n, err := RecordReleaseAll(dir, "shukrad -detach-all"); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
	// With no trail at all it is a no-op, not an error.
	if n, err := RecordReleaseAll(t.TempDir(), "x"); err != nil || n != 0 {
		t.Fatalf("empty dir: %d %v", n, err)
	}
}
