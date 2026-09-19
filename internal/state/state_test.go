package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
)

func TestExplainSlowOnlyWhenMeasured(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "payment-prod-03", PID: 100, Threads: []int{100}}})
	quiet := st.Explain("payment-prod-03", time.Now().UTC())
	for _, line := range quiet.Evidence {
		if strings.Contains(line, "10ms") || strings.Contains(line, "20ms") {
			t.Fatalf("detached counters must not look slow: %v", quiet.Evidence)
		}
	}
	read := make([]uint64, 64)
	read[23] = 10
	st.SetCounters(map[uint32]aggregate.Counters{
		100: {
			BlockIssues:   4,
			BlockRead:     read,
			WakeupCount:   2,
			WakeupDelayNs: 80_000_000,
			OnCPUNs:       1,
		},
	})
	got := st.Explain("payment-prod-03", time.Now().UTC())
	text := strings.Join(got.Evidence, "\n")
	if !strings.Contains(text, "10ms") || !strings.Contains(text, "20ms") {
		t.Fatalf("evidence %v", got.Evidence)
	}
	for _, miss := range got.Missing {
		if miss == "" {
			t.Fatal("missing list emptied")
		}
	}
	if len(got.Missing) != 3 {
		t.Fatalf("missing %v", got.Missing)
	}
}

func TestNetConnectsComeFromEvents(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "payment-prod-03", PID: 100, Threads: []int{100}}})
	st.AddEvent(event.Event{
		Kind: event.KindTCPConnect,
		TS:   time.Now().UTC(),
		VM:   event.VM{Name: "payment-prod-03"},
		Dst:  "1.2.3.4", DPort: 443,
	})
	rows := st.Net("payment-prod-03")
	if len(rows) != 1 || rows[0].Connects != 1 || rows[0].GuestAttributed {
		t.Fatalf("%+v", rows)
	}
}

func TestExportShape(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "payment-prod-03", PID: 1}})
	doc := st.Export()
	if doc.Status.Product != "shukra" || len(doc.VMs) != 1 || doc.Events == nil && len(doc.KVM) < 0 {
		t.Fatalf("%+v", doc)
	}
	if doc.Status.Summary == "" {
		t.Fatal("empty summary")
	}
}
