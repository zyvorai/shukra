package state

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
)

// memRollup is a RollupStore in memory, with the same selection rule as the on-disk one.
type memRollup struct {
	snaps []RollupSnap
	err   error
}

func (m *memRollup) Append(s RollupSnap) error {
	if m.err != nil {
		return m.err
	}
	m.snaps = append(m.snaps, s)
	return nil
}

func (m *memRollup) Around(at time.Time, window time.Duration) (cur, base *RollupSnap, err error) {
	ci := -1
	for i := range m.snaps {
		if !m.snaps[i].At.After(at) {
			ci = i
		}
	}
	if ci < 0 {
		return nil, nil, nil
	}
	cur = &m.snaps[ci]
	for i := ci - 1; i >= 0; i-- {
		if !m.snaps[i].At.After(cur.At.Add(-window)) {
			base = &m.snaps[i]
			break
		}
	}
	return cur, base, nil
}

func newRolled(t *testing.T) (*clocked, *memRollup) {
	t.Helper()
	c := newClocked(t)
	m := &memRollup{}
	c.SetRollup(m)
	return c, m
}

// A vCPU that waited a long time for a CPU only in the second five minutes.
func calmAndStarved() (calm, starved map[uint32]aggregate.Counters) {
	calm = map[uint32]aggregate.Counters{101: {OnCPUNs: 1, WakeupCount: 1000, SchedHist: bucket(map[int]uint64{11: 1000})}}
	starved = map[uint32]aggregate.Counters{101: {OnCPUNs: 2, WakeupCount: 1200, SchedHist: bucket(map[int]uint64{11: 1000, 25: 200})}}
	return
}

func TestASnapshotIsStoredEveryRollEveryNotEveryScan(t *testing.T) {
	c, m := newRolled(t)
	calm, _ := calmAndStarved()
	for i := 0; i < 400; i++ { // a scan every 2 s for 800 s
		c.at(time.Duration(i)*2*time.Second, calm)
	}
	if len(m.snaps) != 3 { // at 0, 300 and 600 s
		t.Fatalf("%d snapshots for 800 s of scans, want 3", len(m.snaps))
	}
	if gap := m.snaps[1].At.Sub(m.snaps[0].At); gap < RollEvery || gap > RollEvery+2*time.Second {
		t.Fatalf("snapshots are %s apart", gap)
	}
}

func TestNothingIsStoredWithoutAStoreOrWithoutVMs(t *testing.T) {
	c := newClocked(t)
	calm, _ := calmAndStarved()
	c.at(0, calm) // no store: must not panic or keep anything
	if s, _ := c.dueRollLocked(t0); s != nil {
		t.Fatal("built a snapshot with no store")
	}
	empty := New("node-07")
	m := &memRollup{}
	empty.SetRollup(m)
	empty.SetCounters(nil)
	if len(m.snaps) != 0 {
		t.Fatal("stored a snapshot with no VMs")
	}
}

func TestTheSnapshotKeepsVCPUsOnTheirOwnAndTheVMTotalWhole(t *testing.T) {
	c, m := newRolled(t)
	c.at(0, map[uint32]aggregate.Counters{
		100: {Exits: map[uint32]uint64{12: 5}, OnCPUNs: 10},
		101: {Exits: map[uint32]uint64{12: 7}, OnCPUNs: 20, PreemptNs: 9, PreemptCount: 2, Preemptors: map[string]uint64{"vm:web": 9}, SchedHist: bucket(map[int]uint64{3: 4})},
	})
	v, ok := rollVM(&m.snaps[0], "db")
	if !ok || v.PID != 100 {
		t.Fatalf("%+v", m.snaps[0])
	}
	if v.Total.Exits[12] != 12 || v.Total.OnCPUNs != 30 {
		t.Fatalf("the total sums every thread: %+v", v.Total)
	}
	if len(v.VCPUs) != 1 || v.VCPUs[0].TID != 101 || v.VCPUs[0].C.PreemptNs != 9 || v.VCPUs[0].C.Preemptors["vm:web"] != 9 {
		t.Fatalf("%+v", v.VCPUs)
	}
	if v.VCPUs[0].C.Exits != nil {
		t.Fatalf("a vCPU keeps only what a scheduling verdict reads, the rest is in the total: %+v", v.VCPUs[0].C)
	}
	// The stored copy must not alias live counters.
	live := c.byPID[101]
	live.Preemptors["vm:web"] = 1
	if v.VCPUs[0].C.Preemptors["vm:web"] != 9 {
		t.Fatal("the snapshot shares memory with the live counters")
	}
}

func TestDropsAndOutcomesAreStoredOnlyWhileTheirProgramsMeasure(t *testing.T) {
	c, m := newRolled(t)
	c.SetPrograms([]Program{{Name: "tap", Status: "attached"}, {Name: "drops", Status: "attached"}})
	c.SetTapSource(func() []TapStat { return []TapStat{{Name: "tap0", Outcomes: Outcomes{OutSyn: 5, OutOK: 5}}} })
	c.SetDropSource(func() []DropStat { return []DropStat{{Tap: "tap0", Reason: "TC_INGRESS", Count: 4}} })
	calm, _ := calmAndStarved()
	c.at(0, calm)
	if m.snaps[0].Outcomes["tap0"].OutOK != 5 || m.snaps[0].Drops["tap0"].Reasons["TC_INGRESS"] != 4 {
		t.Fatalf("%+v", m.snaps[0])
	}
	c.SetPrograms([]Program{{Name: "tap", Status: "detached"}, {Name: "drops", Status: "detached"}})
	c.at(RollEvery, calm)
	if m.snaps[1].Outcomes != nil || m.snaps[1].Drops != nil {
		t.Fatalf("stored counters for programs that were not measuring: %+v", m.snaps[1])
	}
}

// The reason for the feature. The verdict for a past time must weigh the window between two stored snapshots and
// not the lifetime, and not the snapshots around now.
func TestAPastVerdictWeighsTheWindowBetweenTwoStoredSnapshots(t *testing.T) {
	c, _ := newRolled(t)
	calm, starved := calmAndStarved()
	c.at(0, calm)
	c.at(5*time.Minute, starved) // the vCPU starved in this five minutes
	c.at(10*time.Minute, starved)
	c.at(15*time.Minute, starved) // and was calm after it

	during := c.ExplainAt("db", t0.Add(5*time.Minute), 5*time.Minute)
	f := causeOf(during, "host_cpu_contention")
	if f == nil || f.Confidence != "high" || !strings.Contains(f.Evidence[0], "vCPU thread 101") {
		t.Fatalf("the starved window must be found: %+v", during.Findings)
	}
	if during.At != t0.Add(5*time.Minute).Format(time.RFC3339) || !strings.Contains(during.Resolution, "5m0s snapshots") {
		t.Fatalf("it must say when and how coarse: at=%q resolution=%q", during.At, during.Resolution)
	}
	after := c.ExplainAt("db", t0.Add(15*time.Minute), 5*time.Minute)
	if causeOf(after, "host_cpu_contention") != nil {
		t.Fatalf("a calm window read as starved because the lifetime counters were: %+v", after.Findings)
	}
	// A longer window that includes the bad five minutes finds it again.
	if causeOf(c.ExplainAt("db", t0.Add(15*time.Minute), 15*time.Minute), "host_cpu_contention") == nil {
		t.Fatal("a 15-minute window over the bad period must find it")
	}
}

func TestAPastVerdictNamesWhoTookTheCPU(t *testing.T) {
	c, _ := newRolled(t)
	idle := map[uint32]aggregate.Counters{101: {OnCPUNs: 1_000 * ms, WakeupCount: 1}}
	pre := map[uint32]aggregate.Counters{101: {OnCPUNs: 1_500 * ms, WakeupCount: 2, PreemptNs: 900 * ms, PreemptCount: 40, Preemptors: map[string]uint64{"vm:web": 800 * ms, "kworker": 100 * ms}}}
	c.at(0, idle)
	c.at(5*time.Minute, pre)
	f := causeOf(c.ExplainAt("db", t0.Add(5*time.Minute), 5*time.Minute), "cpu_preempted")
	if f == nil || !strings.Contains(strings.Join(f.Evidence, " "), "VM web") {
		t.Fatalf("%+v", f)
	}
}

func TestAPastVerdictSaysWhyItHasNothingRatherThanGuessing(t *testing.T) {
	calm, _ := calmAndStarved()
	cases := map[string]func() Explain{
		"no store": func() Explain {
			c := newClocked(t)
			return c.ExplainAt("db", t0.Add(time.Hour), time.Hour)
		},
		"nothing that old": func() Explain {
			c, _ := newRolled(t)
			c.at(time.Hour, calm)
			return c.ExplainAt("db", t0, 10*time.Minute)
		},
		"the daemon was not running then": func() Explain {
			c, _ := newRolled(t)
			c.at(0, calm)
			c.at(5*time.Minute, calm)
			return c.ExplainAt("db", t0.Add(3*time.Hour), 5*time.Minute)
		},
		"not enough before it": func() Explain {
			c, _ := newRolled(t)
			c.at(0, calm)
			return c.ExplainAt("db", t0, 15*time.Minute)
		},
	}
	for name, run := range cases {
		ex := run()
		if len(ex.Findings) != 1 || ex.Findings[0].Cause != "no_history" || ex.Findings[0].Summary == "" || ex.Window != "none" {
			t.Errorf("%s: %+v", name, ex)
		}
		if ex.Events == nil || ex.Evidence == nil {
			t.Errorf("%s: an empty list must be [] and not null", name)
		}
	}
	c, _ := newRolled(t)
	c.at(0, calm)
	c.at(5*time.Minute, calm)
	if ex := c.ExplainAt("nobody", t0.Add(5*time.Minute), 5*time.Minute); ex.Findings[0].Cause != "unknown_vm" {
		t.Fatalf("%+v", ex.Findings)
	}
}

func TestAStoreThatFailsDoesNotStopTheDaemonAndIsReportedOnce(t *testing.T) {
	c, m := newRolled(t)
	m.err = errStore
	calm, _ := calmAndStarved()
	c.at(0, calm)
	c.at(RollEvery, calm)
	c.at(2*RollEvery, calm)
	if !c.rollWarned {
		t.Fatal("a failing store was not noticed")
	}
	if ex := c.ExplainAt("db", t0, 10*time.Minute); ex.Findings[0].Cause != "no_history" {
		t.Fatalf("%+v", ex.Findings)
	}
}

var errStore = &storeErr{}

type storeErr struct{}

func (*storeErr) Error() string { return "disk full" }

func TestAnIncidentBundleHoldsTheWindowsDetectionsAndNothingFromTheConfiguration(t *testing.T) {
	c, _ := newRolled(t)
	c.SetConfig(ConfigInfo{Listen: "0.0.0.0:30970", KeyLen: 32, DataDir: "/var/lib/secret-dir", RulesFile: "/etc/shukra/detections.yaml"})
	calm, starved := calmAndStarved()
	c.at(0, calm)
	c.at(5*time.Minute, starved)
	c.at(10*time.Minute, starved)
	c.now = t0.Add(10 * time.Minute)
	for _, d := range []struct {
		vm string
		at time.Duration
	}{{"db", 1 * time.Minute}, {"db", 7 * time.Minute}, {"db", 9 * time.Minute}, {"web", 8 * time.Minute}} {
		c.AddEvent(event.Event{Kind: event.KindDetection, TS: t0.Add(d.at), VM: event.VM{Name: d.vm}, Rule: "r", Message: "m " + d.at.String()})
	}
	inc := c.Incident("db", t0.Add(10*time.Minute), 5*time.Minute+30*time.Second)
	if len(inc.Detections) != 2 {
		t.Fatalf("only db's detections inside the window: %+v", inc.Detections)
	}
	if causeOf(inc.Explain, "host_cpu_contention") == nil && inc.Explain.Window == "" {
		t.Fatalf("%+v", inc.Explain)
	}
	if inc.Detections == nil || inc.Events == nil || inc.Isolations == nil || inc.AllowList == nil {
		t.Fatal("every list in the bundle must be [] and not null")
	}
	b, _ := json.Marshal(inc)
	for _, secret := range []string{"0.0.0.0:30970", "secret-dir", "/etc/shukra/detections.yaml", "keyLen"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("the bundle leaked configuration: %q", secret)
		}
	}
	if inc.At == "now" || inc.Note == "" {
		t.Fatalf("%+v", inc)
	}
	if live := c.Incident("db", time.Time{}, 0); live.At != "now" {
		t.Fatalf("a bundle with no time is about now: %q", live.At)
	}
}

// A store that hands back two snapshots too close together says nothing more than one snapshot would.
type nearStore struct{ a, b RollupSnap }

func (n *nearStore) Append(RollupSnap) error { return nil }
func (n *nearStore) Around(time.Time, time.Duration) (*RollupSnap, *RollupSnap, error) {
	return &n.b, &n.a, nil
}

func TestTwoSnapshotsTooCloseTogetherAreNotAWindow(t *testing.T) {
	c := newClocked(t)
	one := RollupSnap{At: t0, VMs: []VMRoll{{Name: "db", PID: 100}}}
	two := RollupSnap{At: t0.Add(time.Minute), VMs: []VMRoll{{Name: "db", PID: 100}}}
	c.SetRollup(&nearStore{a: one, b: two})
	if ex := c.ExplainAt("db", t0.Add(time.Minute), 10*time.Minute); ex.Findings[0].Cause != "no_history" {
		t.Fatalf("%+v", ex.Findings)
	}
}

func TestALiveVerdictAndTheRecorderNeverHaveNullLists(t *testing.T) {
	c := newClocked(t)
	calm, _ := calmAndStarved()
	c.at(0, calm)
	ex := c.ExplainOver("db", t0.Add(time.Minute), time.Minute)
	if ex.Events == nil || ex.Evidence == nil || ex.Missing == nil {
		t.Fatalf("a nil list encodes as null: %+v", ex)
	}
	if got := c.Recorder("db", time.Minute, t0); got == nil {
		t.Fatal("the recorder returned nil for a VM with no events")
	}
	b, _ := json.Marshal(ex)
	if strings.Contains(string(b), `":null`) {
		t.Fatalf("a null in the verdict: %s", b)
	}
}
