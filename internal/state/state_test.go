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

func TestSeqCursorSurvivesWrap(t *testing.T) {
	st := New("node-07")
	const n = MaxEvents + 100
	for i := 0; i < n; i++ {
		st.AddEvent(event.Event{
			Kind: event.KindTCPConnect, VM: event.VM{Name: "db"}, PID: 1, Dst: "1.2.3.4",
		})
	}
	if st.Seq() != n {
		t.Fatalf("seq %d", st.Seq())
	}
	if got := len(st.Events("")); got != MaxEvents {
		t.Fatalf("kept %d", got)
	}
	// A client that saw the newest event asks for nothing new, even though the
	// list has wrapped. A count-based cursor would be stuck here.
	if got := st.EventsSince("", n); len(got) != 0 {
		t.Fatalf("since newest: %d", len(got))
	}
	st.AddEvent(event.Event{Kind: event.KindTCPConnect, VM: event.VM{Name: "db"}, PID: 1})
	got := st.EventsSince("", n)
	if len(got) != 1 || got[0].Seq != n+1 {
		t.Fatalf("after wrap: %+v", got)
	}
	// Connect totals are a counter, not a recount of the wrapped list.
	rows := st.Net("db")
	if len(rows) != 1 || rows[0].Connects != n+1 {
		t.Fatalf("connects %+v", rows)
	}
}

func TestDetectionsAreBounded(t *testing.T) {
	st := New("node-07")
	for i := 0; i < MaxEvents+5; i++ {
		st.AddEvent(event.Event{Kind: event.KindDetection, Message: "x"})
	}
	if got := len(st.Detections("")); got != MaxEvents {
		t.Fatalf("detections %d", got)
	}
}

func TestReadyAfterFirstPrograms(t *testing.T) {
	st := New("node-07")
	if st.Ready() {
		t.Fatal("ready before the first scan")
	}
	st.SetPrograms(nil)
	if !st.Ready() {
		t.Fatal("not ready after SetPrograms")
	}
}

func TestIsolationsAreListed(t *testing.T) {
	st := New("node-07")
	st.Isolate("db", "shukractl")
	got := st.Isolations()
	if len(got) != 1 || got[0].VM != "db" || got[0].Applied {
		t.Fatalf("%+v", got)
	}
}

func TestDetectionHookRunsAfterUnlockAndSkipsRestore(t *testing.T) {
	st := New("node-07")
	var got []string
	st.OnDetection(func(e event.Event) {
		// Would deadlock if AddEvent still held the lock.
		got = append(got, e.Rule+":"+string(rune('0'+len(st.Detections("")))))
	})
	st.AddEvent(event.Event{Kind: event.KindTCPConnect, PID: 1})
	st.AddEvent(event.Event{Kind: event.KindDetection, Rule: "a"})
	st.Restore([]event.Event{{Kind: event.KindDetection, Rule: "old", Seq: 5}}, nil, nil)
	if len(got) != 1 || got[0] != "a:1" {
		t.Fatalf("hook calls: %v", got)
	}
}

func TestSuppressedAndSinkStats(t *testing.T) {
	st := New("node-07")
	if st.SinkStats() != nil {
		t.Fatal("stats without a source")
	}
	st.AddSuppressed(2)
	st.AddSuppressed(1)
	st.SetSinkStats(func() []SinkStat { return []SinkStat{{Name: "webhook", Sent: 4}} })
	if st.Suppressed() != 3 || len(st.SinkStats()) != 1 || st.SinkStats()[0].Sent != 4 {
		t.Fatalf("%d %+v", st.Suppressed(), st.SinkStats())
	}
}

func TestNetConnectsTakeTheLargerOfKernelCounterAndEvents(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	connect := func() {
		st.AddEvent(event.Event{Kind: event.KindTCPConnect, VM: event.VM{Name: "db"}, PID: 100, Dst: "1.1.1.1"})
	}
	connect()
	connect()
	// No program attached: only the two events exist.
	if rows := st.Net("db"); len(rows) != 1 || rows[0].Connects != 2 {
		t.Fatalf("events only: %+v", rows)
	}
	// The kernel counter saw 5, and the ring delivered 2 of them. The same
	// connects seen two ways must not be added together.
	st.SetCounters(map[uint32]aggregate.Counters{100: {Connects: 5}})
	if rows := st.Net("db"); len(rows) != 1 || rows[0].Connects != 5 {
		t.Fatalf("counter ahead of events: %+v", rows)
	}
	// If the events are somehow ahead of a stale counter, show what was seen.
	connect()
	connect()
	connect()
	connect()
	if rows := st.Net("db"); rows[0].Connects != 6 {
		t.Fatalf("events ahead of counter: %+v", rows)
	}
}
