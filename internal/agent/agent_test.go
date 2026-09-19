package agent

import (
	"os"
	"path/filepath"
	"testing"

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
