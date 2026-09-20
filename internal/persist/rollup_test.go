package persist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/state"
)

var r0 = time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)

func snapAt(d time.Duration, marker uint64) state.RollupSnap {
	return state.RollupSnap{At: r0.Add(d), VMs: []state.VMRoll{{
		Name: "db", PID: 100, Taps: []string{"tap0"},
		Total: aggregate.Counters{
			OnCPUNs: marker, Exits: map[uint32]uint64{12: marker, 48: 3}, ExitNs: map[uint32]uint64{12: 900},
			SchedHist: make([]uint64, 64), Preemptors: map[string]uint64{"vm:web": marker},
		},
		VCPUs: []state.VCPURoll{{TID: 101, Comm: "CPU 0/KVM", C: aggregate.Counters{PreemptNs: marker}}},
	}}}
}

func openTest(t *testing.T, max int64) *Rollup {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, rollupFile)
	l, err := OpenLog(path, max)
	if err != nil {
		t.Fatal(err)
	}
	r := &Rollup{log: l, path: path}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestASnapshotSurvivesTheRoundTripExactly(t *testing.T) {
	r := openTest(t, DefaultMaxBytes)
	want := snapAt(0, 42)
	want.Drops = map[string]state.DropRoll{"tap0": {Reasons: map[string]uint64{"TC_INGRESS": 7}, Shukra: 2}}
	want.Outcomes = map[string]state.Outcomes{"tap0": {OutSyn: 9, OutOK: 8, OutRefused: 1}}
	if err := r.Append(want); err != nil {
		t.Fatal(err)
	}
	cur, _, err := r.Around(r0.Add(time.Minute), 5*time.Minute)
	if err != nil || cur == nil {
		t.Fatalf("%v %v", cur, err)
	}
	if !reflect.DeepEqual(*cur, want) {
		t.Fatalf("what came back is not what went in:\n got %+v\nwant %+v", *cur, want)
	}
}

func TestAroundPicksTheNewestAtOrBeforeAndABaseAWindowOlder(t *testing.T) {
	r := openTest(t, DefaultMaxBytes)
	for i := 0; i < 6; i++ { // 0, 5, 10, 15, 20, 25 minutes
		if err := r.Append(snapAt(time.Duration(i)*5*time.Minute, uint64(i))); err != nil {
			t.Fatal(err)
		}
	}
	cur, base, err := r.Around(r0.Add(17*time.Minute), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if cur.VMs[0].Total.OnCPUNs != 3 || base.VMs[0].Total.OnCPUNs != 1 { // 15 min and 5 min
		t.Fatalf("cur %d base %d", cur.VMs[0].Total.OnCPUNs, base.VMs[0].Total.OnCPUNs)
	}
	// Exactly at a snapshot's time is that snapshot.
	cur, _, _ = r.Around(r0.Add(20*time.Minute), 5*time.Minute)
	if cur.VMs[0].Total.OnCPUNs != 4 {
		t.Fatalf("%d", cur.VMs[0].Total.OnCPUNs)
	}
	// Before the first there is nothing, and with too little before there is a current but no base.
	if cur, _, _ = r.Around(r0.Add(-time.Second), time.Minute); cur != nil {
		t.Fatal("a snapshot from the future of the question")
	}
	cur, base, _ = r.Around(r0.Add(5*time.Minute), 30*time.Minute)
	if cur == nil || base != nil {
		t.Fatalf("cur %v base %v", cur, base)
	}
}

func TestATornLastLineIsIgnoredAndEverythingBeforeItIsKept(t *testing.T) {
	r := openTest(t, DefaultMaxBytes)
	for i := 0; i < 3; i++ {
		_ = r.Append(snapAt(time.Duration(i)*5*time.Minute, uint64(i)))
	}
	f, _ := os.OpenFile(r.path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"at":"2026-09-20T03:15:00Z","vms":[{"name":"d`) // a crash mid-write
	f.Close()
	cur, base, err := r.Around(r0.Add(time.Hour), 5*time.Minute)
	if err != nil || cur == nil || base == nil || cur.VMs[0].Total.OnCPUNs != 2 {
		t.Fatalf("%+v %+v %v", cur, base, err)
	}
}

func TestRollingKeepsOlderSnapshotsReadableAndDropsTheOldestOfAll(t *testing.T) {
	one, _ := jsonSize(snapAt(0, 1))
	r := openTest(t, int64(one*3)) // the file holds three, then rolls to .1
	for i := 0; i < 9; i++ {
		if err := r.Append(snapAt(time.Duration(i)*5*time.Minute, uint64(i))); err != nil {
			t.Fatal(err)
		}
	}
	all, err := r.scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 4 || len(all) > 7 {
		t.Fatalf("%d snapshots kept of 9 with room for about 3 per file", len(all))
	}
	for i := 1; i < len(all); i++ {
		if !all[i].at.After(all[i-1].at) {
			t.Fatal("snapshots are not in time order across the rolled file")
		}
	}
	if !all[len(all)-1].at.Equal(r0.Add(40 * time.Minute)) {
		t.Fatalf("the newest was lost: %v", all[len(all)-1].at)
	}
	if !all[0].at.After(r0) {
		t.Fatal("the oldest snapshot should have rolled out")
	}
	// One from the rolled file is still queryable.
	cur, _, err := r.Around(all[0].at, 5*time.Minute)
	if err != nil || cur == nil || !cur.At.Equal(all[0].at) {
		t.Fatalf("%+v %v", cur, err)
	}
}

func TestAReopenedLogKeepsAnsweringAndKeepsAppending(t *testing.T) {
	dir := t.TempDir()
	r, err := OpenRollup(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Append(snapAt(0, 1))
	_ = r.Close()
	r, err = OpenRollup(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_ = r.Append(snapAt(5*time.Minute, 2))
	cur, base, _ := r.Around(r0.Add(5*time.Minute), 5*time.Minute)
	if cur == nil || base == nil || cur.VMs[0].Total.OnCPUNs != 2 || base.VMs[0].Total.OnCPUNs != 1 {
		t.Fatalf("%+v %+v", cur, base)
	}
	fi, err := os.Stat(filepath.Join(dir, rollupFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the snapshot file names VMs and taps and must be private: %v %v", fi, err)
	}
}

func TestNoFileMeansNoHistoryNotAnError(t *testing.T) {
	r := &Rollup{path: filepath.Join(t.TempDir(), "absent.jsonl")}
	cur, base, err := r.Around(r0, time.Minute)
	if err != nil || cur != nil || base != nil {
		t.Fatalf("%v %v %v", cur, base, err)
	}
}

// jsonSize is how many bytes a snapshot takes as a log line.
func jsonSize(s state.RollupSnap) (int, error) {
	b, err := json.Marshal(s)
	return len(b) + 1, err
}

func TestAttachGivesTheStateARollupSoAPastVerdictHasSomewhereToLook(t *testing.T) {
	st := state.New("node-07")
	if ex := st.ExplainAt("db", time.Now(), time.Hour); !contains(ex.Findings[0].Summary, "No history is kept") {
		t.Fatalf("without a data directory the answer must say how to get history: %+v", ex.Findings)
	}
	h, err := Attach(st, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ex := st.ExplainAt("db", time.Now(), time.Hour)
	if contains(ex.Findings[0].Summary, "No history is kept") || !contains(ex.Findings[0].Summary, "No snapshot is stored") {
		t.Fatalf("Attach did not connect the rollup: %+v", ex.Findings)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
