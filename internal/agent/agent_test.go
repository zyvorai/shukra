package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/state"
)

func TestIngestWatchlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watch.yaml")
	if err := os.WriteFile(path, []byte("destinations:\n  - cidr: 185.0.0.0/8\n    severity: high\n    name: unexpected-egress\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := state.New("node-07")
	ag, err := New(st, dir, path, "node-07")
	if err != nil {
		t.Fatal(err)
	}
	st.SetVMs([]identity.VM{{
		Name: "payment-prod-03", UUID: "u", Runtime: "qemu", PID: 100, Threads: []int{100, 101},
	}})
	ag.Ingest(event.Event{Kind: event.KindTCPConnect, PID: 101, TGID: 100, Dst: "185.9.1.1", DPort: 443, Comm: "qemu-system-x86_64"})
	dets := st.Detections("payment-prod-03")
	if len(dets) != 1 || dets[0].GuestAttributed || dets[0].Attribution != event.AttributionQEMU || dets[0].Severity != "high" {
		t.Fatalf("%+v", dets)
	}
	if len(st.Events("payment-prod-03")) != 2 {
		t.Fatalf("events %#v", st.Events("payment-prod-03"))
	}
}

func TestUnexpectedExec(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "200"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "200", "status"), []byte("Name:\tcurl\nPPid:\t100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "201"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "201", "status"), []byte("Name:\tqemu\nPPid:\t100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := state.New("node-07")
	ag, err := New(st, root, "", "node-07")
	if err != nil {
		t.Fatal(err)
	}
	st.SetVMs([]identity.VM{{Name: "payment-prod-03", PID: 100, Threads: []int{100}}})
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 200, Comm: "curl"})
	dets := st.Detections("payment-prod-03")
	if len(dets) != 1 || dets[0].Message != "unexpected exec curl" || dets[0].GuestAttributed {
		t.Fatalf("%+v", dets)
	}
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 201, Comm: "qemu-system-x86"})
	if len(st.Detections("payment-prod-03")) != 1 {
		t.Fatalf("qemu binary was flagged: %+v", st.Detections("payment-prod-03"))
	}
}

func TestReloadKeepsPreviousListOnBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watch.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("destinations:\n  - cidr: 185.0.0.0/8\n    name: a\n")
	st := state.New("node-07")
	ag, err := New(st, dir, path, "node-07")
	if err != nil {
		t.Fatal(err)
	}
	st.SetVMs([]identity.VM{{Name: "db", PID: 100}})
	connect := func(dst string) {
		ag.Ingest(event.Event{Kind: event.KindTCPConnect, PID: 100, TGID: 100, Dst: dst, DPort: 443})
	}

	write("destinations:\n  - cidr: not-a-cidr\n")
	if err := ag.Reload(); err == nil {
		t.Fatal("bad cidr reloaded")
	}
	connect("185.1.1.1")
	if len(st.Detections("db")) != 1 {
		t.Fatal("old rule lost after a failed reload")
	}

	write("destinations:\n  - cidr: 203.0.113.0/24\n    name: b\n")
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	connect("185.1.1.1")
	connect("203.0.113.9")
	if got := len(st.Detections("db")); got != 2 {
		t.Fatalf("detections %d, want the old hit plus one for the new rule only", got)
	}
}

// newAgent writes a detection file and returns an agent using it, with one VM.
func newAgent(t *testing.T, yaml string) (*Agent, *state.State, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "detections.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	st := state.New("node-07")
	ag, err := New(st, root, path, "node-07")
	if err != nil {
		t.Fatal(err)
	}
	st.SetVMs([]identity.VM{{Name: "db", UUID: "u", Runtime: "qemu", PID: 100, Threads: []int{100, 101}}})
	return ag, st, root
}

func connect(ag *Agent, ts time.Time, dst string, port uint16) {
	ag.Ingest(event.Event{Kind: event.KindTCPConnect, TS: ts, PID: 101, TGID: 100, Dst: dst, DPort: port})
}

func TestPortRuleNamesTheRule(t *testing.T) {
	ag, st, _ := newAgent(t, "ports:\n  - port: 25\n    name: smtp-egress\n    severity: medium\n")
	now := time.Now().UTC()
	connect(ag, now, "9.9.9.9", 443)
	if len(st.Detections("db")) != 0 {
		t.Fatal("port 443 detected")
	}
	connect(ag, now, "9.9.9.9", 25)
	got := st.Detections("db")
	if len(got) != 1 || got[0].Rule != "smtp-egress" || got[0].Severity != "medium" ||
		got[0].DPort != 25 || got[0].GuestAttributed || got[0].VM.Name != "db" {
		t.Fatalf("%+v", got)
	}
}

func TestSuppressionCollapsesRepeatsAndReportsThem(t *testing.T) {
	ag, st, _ := newAgent(t, "suppress: 1m\ndestinations:\n  - cidr: 185.0.0.0/8\n    name: egress\n")
	t0 := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		connect(ag, t0.Add(time.Duration(i)*time.Second), "185.1.1.1", 443)
	}
	if got := len(st.Detections("db")); got != 1 {
		t.Fatalf("%d detections for four identical connects", got)
	}
	if st.Suppressed() != 3 {
		t.Fatalf("suppressed %d", st.Suppressed())
	}
	// A different destination is a different detection.
	connect(ag, t0.Add(5*time.Second), "185.2.2.2", 443)
	if got := len(st.Detections("db")); got != 2 {
		t.Fatalf("%d detections", got)
	}
	// After the window the repeat goes through and says what it stood in for.
	connect(ag, t0.Add(2*time.Minute), "185.1.1.1", 443)
	got := st.Detections("db")
	if len(got) != 3 || !strings.Contains(got[2].Message, "(3 similar suppressed)") {
		t.Fatalf("%+v", got)
	}
	// Every raw connect is still an event. Only the alert is collapsed.
	if n := len(st.Events("db")); n != 6+3 { // six connects, three detections
		t.Fatalf("events %d", n)
	}
}

func TestSuppressZeroAlertsEveryTime(t *testing.T) {
	ag, st, _ := newAgent(t, "suppress: 0s\ndestinations:\n  - cidr: 185.0.0.0/8\n    name: egress\n")
	now := time.Now().UTC()
	connect(ag, now, "185.1.1.1", 443)
	connect(ag, now, "185.1.1.1", 443)
	if got := len(st.Detections("db")); got != 2 {
		t.Fatalf("%d", got)
	}
}

func TestExecAllowAddsToBuiltins(t *testing.T) {
	ag, st, root := newAgent(t, "exec_allow: [backup-agent]\n")
	for pid, name := range map[string]string{"300": "backup-agent", "301": "nc"} {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "status"), []byte("Name:\t"+name+"\nPPid:\t100\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 300, Comm: "backup-agent"})
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 301, Comm: "nc"})
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 302, TGID: 100, Comm: "qemu-system-x86"})
	got := st.Detections("db")
	if len(got) != 1 || got[0].Rule != "unexpected-exec" || !strings.Contains(got[0].Message, "nc") {
		t.Fatalf("%+v", got)
	}
}

func TestThresholdDetectionEndToEnd(t *testing.T) {
	ag, st, _ := newAgent(t, `
thresholds:
  - name: exit-storm
    metric: kvm_exits_per_sec
    value: 1000
    window: 10s
    severity: high
`)
	vms := st.VMs()
	t0 := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	at := func(sec int, exits uint64) {
		ag.evaluate(t0.Add(time.Duration(sec)*time.Second), vms, map[uint32]aggregate.Counters{
			101: {Exits: map[uint32]uint64{1: exits}},
			999: {Exits: map[uint32]uint64{1: 1 << 40}}, // a non-QEMU pid: host rollup, never a VM alert
		})
	}
	at(0, 0)
	at(5, 500_000)
	if len(st.Detections("db")) != 0 {
		t.Fatal("fired before a full window")
	}
	at(10, 1_000_000)
	got := st.Detections("db")
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	d := got[0]
	if d.Rule != "exit-storm" || d.Severity != "high" || d.VM.Name != "db" || d.TGID != 100 ||
		d.GuestAttributed || d.Attribution != event.AttributionQEMU || !strings.Contains(d.Message, "kvm_exits_per_sec") {
		t.Fatalf("%+v", d)
	}
	// Still crossed on the next tick: suppressed, not repeated.
	at(12, 1_200_000)
	if len(st.Detections("db")) != 1 || st.Suppressed() != 1 {
		t.Fatalf("detections %d suppressed %d", len(st.Detections("db")), st.Suppressed())
	}
}

func TestReloadKeepsSuppressionState(t *testing.T) {
	ag, st, root := newAgent(t, "destinations:\n  - cidr: 185.0.0.0/8\n    name: egress\n")
	now := time.Now().UTC()
	connect(ag, now, "185.1.1.1", 443)
	if err := os.WriteFile(filepath.Join(root, "detections.yaml"), []byte("destinations:\n  - cidr: 185.0.0.0/8\n    name: egress\nports:\n  - port: 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	connect(ag, now.Add(time.Second), "185.1.1.1", 443)
	if got := len(st.Detections("db")); got != 1 {
		t.Fatalf("a reload let a repeat through: %d", got)
	}
}

func TestStrictReloadRejectsTypoAndKeepsRules(t *testing.T) {
	ag, st, root := newAgent(t, "destinations:\n  - cidr: 185.0.0.0/8\n    name: egress\n")
	if err := os.WriteFile(filepath.Join(root, "detections.yaml"), []byte("destination:\n  - cidr: 185.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err == nil {
		t.Fatal("misspelled section accepted")
	}
	connect(ag, time.Now().UTC(), "185.1.1.1", 443)
	if len(st.Detections("db")) != 1 {
		t.Fatal("old rules lost after a rejected reload")
	}
}

func TestExecAndExitJoinByKernelPPIDWithoutProc(t *testing.T) {
	// No /proc entries at all: the process is already gone, as short-lived ones are.
	ag, st, _ := newAgent(t, "")
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 500, PPID: 100, Comm: "curl"})
	ag.Ingest(event.Event{Kind: event.KindExit, PID: 500, PPID: 100, Comm: "curl"})
	evs := st.Events("db")
	kinds := map[event.Kind]int{}
	for _, e := range evs {
		kinds[e.Kind]++
		if e.GuestAttributed || e.Attribution != event.AttributionQEMU || e.TGID != 100 {
			t.Fatalf("%+v", e)
		}
	}
	if kinds[event.KindExec] != 1 || kinds[event.KindExit] != 1 || kinds[event.KindDetection] != 1 {
		t.Fatalf("%v", kinds)
	}
	// Only the exec is a detection. An exit is never "unexpected".
	if d := st.Detections("db"); len(d) != 1 || d[0].Rule != "unexpected-exec" || d[0].PPID != 100 {
		t.Fatalf("%+v", d)
	}
}

func TestKernelPPIDOfAnAllowedProcessIsAttributedButNotFlagged(t *testing.T) {
	ag, st, _ := newAgent(t, "exec_allow: [backup-agent]\n")
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 500, PPID: 100, Comm: "backup-agent"})
	ag.Ingest(event.Event{Kind: event.KindExec, PID: 501, PPID: 100, Comm: "qemu-img"}) // not allowed
	got := st.Events("db")
	if len(got) != 3 { // both execs, plus one detection for qemu-img
		t.Fatalf("%+v", got)
	}
	if d := st.Detections("db"); len(d) != 1 || !strings.Contains(d[0].Message, "qemu-img") {
		t.Fatalf("%+v", d)
	}
}

func TestUnrelatedParentIsNotJoined(t *testing.T) {
	ag, st, _ := newAgent(t, "")
	ag.Ingest(event.Event{Kind: event.KindExit, PID: 500, PPID: 4321, Comm: "sh"})
	if len(st.Events("db")) != 0 || len(st.Detections("")) != 0 {
		t.Fatal("an exit under an unrelated parent was attributed to a VM")
	}
	if len(st.Events("")) != 1 {
		t.Fatal("the event should still be recorded, unattributed")
	}
}

func TestCPUVendorFromProc(t *testing.T) {
	root := t.TempDir()
	if got := cpuVendor(root); got != "" {
		t.Fatalf("no cpuinfo: %q", got)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "cpuinfo"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Xeon\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\n")
	if got := cpuVendor(root); got != "GenuineIntel" {
		t.Fatalf("%q", got)
	}
	write("processor\t: 0\nBogoMIPS\t: 48.00\nCPU implementer\t: 0x61\n") // arm64: no vendor_id
	if got := cpuVendor(root); got != "" {
		t.Fatalf("arm64: %q", got)
	}
}

func TestRefreshSetsVendorSoExitReasonsAreNamed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cpuinfo"), []byte("vendor_id\t: GenuineIntel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := state.New("node-07")
	ag, err := New(st, root, "", "node-07")
	if err != nil {
		t.Fatal(err)
	}
	ag.Refresh()
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	st.SetCounters(map[uint32]aggregate.Counters{100: {Exits: map[uint32]uint64{12: 3}}})
	rows := st.KVM("db")
	if len(rows) != 1 || rows[0].Top[0].Name != "hlt" {
		t.Fatalf("%+v", rows)
	}
}

// addQEMU writes a QEMU process into a fake /proc.
func addQEMU(t *testing.T, root, pid, name string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(filepath.Join(dir, "task", pid), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := "qemu-system-x86_64\x00-name\x00guest=" + name + ",debug-threads=on\x00-uuid\x00u-" + name + "\x00"
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd), 0o644); err != nil {
		t.Fatal(err)
	}
}

func kinds(st *state.State, k event.Kind) []event.Event {
	var out []event.Event
	for _, e := range st.Events("") {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func TestVMStartAndStopEvents(t *testing.T) {
	root := t.TempDir()
	addQEMU(t, root, "100", "already-running")
	st := state.New("node-07")
	ag, err := New(st, root, "", "node-07")
	if err != nil {
		t.Fatal(err)
	}
	ag.Refresh()
	if len(kinds(st, event.KindVMStart)) != 0 {
		t.Fatal("a VM that was already running at daemon start was announced as new")
	}

	addQEMU(t, root, "200", "db")
	ag.Refresh()
	starts := kinds(st, event.KindVMStart)
	if len(starts) != 1 || starts[0].VM.Name != "db" || starts[0].PID != 200 || starts[0].Attribution != event.AttributionQEMU || starts[0].GuestAttributed {
		t.Fatalf("%+v", starts)
	}
	ag.Refresh()
	if len(kinds(st, event.KindVMStart)) != 1 {
		t.Fatal("start reported twice")
	}

	// One missed scan is not a stop: Scan skips a process it cannot read for a moment.
	if err := os.Rename(filepath.Join(root, "200"), filepath.Join(root, "hidden")); err != nil {
		t.Fatal(err)
	}
	ag.Refresh()
	if len(kinds(st, event.KindVMStop)) != 0 {
		t.Fatal("stopped after a single missed scan")
	}
	if err := os.Rename(filepath.Join(root, "hidden"), filepath.Join(root, "200")); err != nil {
		t.Fatal(err)
	}
	ag.Refresh() // seen again: the miss count resets, and it is not a new VM
	if len(kinds(st, event.KindVMStop)) != 0 || len(kinds(st, event.KindVMStart)) != 1 {
		t.Fatal("a blip looked like a restart")
	}

	if err := os.RemoveAll(filepath.Join(root, "200")); err != nil {
		t.Fatal(err)
	}
	ag.Refresh()
	ag.Refresh()
	stops := kinds(st, event.KindVMStop)
	if len(stops) != 1 || stops[0].VM.Name != "db" || !strings.Contains(stops[0].Message, "gone") {
		t.Fatalf("%+v", stops)
	}
	ag.Refresh()
	if len(kinds(st, event.KindVMStop)) != 1 {
		t.Fatal("stop reported twice")
	}
}

func TestRestartIsAStopAndAStart(t *testing.T) {
	root := t.TempDir()
	addQEMU(t, root, "100", "db")
	st := state.New("node-07")
	ag, _ := New(st, root, "", "node-07")
	ag.Refresh()
	if err := os.RemoveAll(filepath.Join(root, "100")); err != nil {
		t.Fatal(err)
	}
	addQEMU(t, root, "300", "db") // same name, new pid
	ag.Refresh()
	ag.Refresh()
	if len(kinds(st, event.KindVMStart)) != 1 || len(kinds(st, event.KindVMStop)) != 1 {
		t.Fatalf("starts %d stops %d", len(kinds(st, event.KindVMStart)), len(kinds(st, event.KindVMStop)))
	}
	if kinds(st, event.KindVMStart)[0].PID != 300 || kinds(st, event.KindVMStop)[0].PID != 100 {
		t.Fatal("pids do not identify which instance started and which stopped")
	}
}
