package recorder

import (
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

func TestEvictsOldest(t *testing.T) {
	r := New(3)
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		r.Add(event.Event{
			Kind: event.KindExec,
			TS:   base.Add(time.Duration(i) * time.Second),
			VM:   event.VM{Name: "payment-prod-03", Runtime: "qemu"},
			PID:  uint32(i),
		})
	}
	got := r.Window("payment-prod-03", time.Hour, base.Add(time.Minute))
	if len(got) != 3 {
		t.Fatalf("len %d", len(got))
	}
	if got[0].PID != 2 || got[2].PID != 4 {
		t.Fatalf("order %#v", got)
	}
	if got[0].Product != "shukra" || got[0].GuestAttributed || got[0].Attribution != event.AttributionQEMU {
		t.Fatalf("normalize %+v", got[0])
	}
}

func TestWindow(t *testing.T) {
	r := New(10)
	now := time.Date(2026, 9, 19, 9, 42, 10, 0, time.UTC)
	r.Add(event.Event{Kind: event.KindExec, TS: now.Add(-90 * time.Second), VM: event.VM{Name: "api-01"}})
	r.Add(event.Event{Kind: event.KindTCPConnect, TS: now.Add(-20 * time.Second), VM: event.VM{Name: "api-01"}, Dst: "10.0.0.1"})
	got := r.Window("api-01", 60*time.Second, now)
	if len(got) != 1 || got[0].Kind != event.KindTCPConnect {
		t.Fatalf("%#v", got)
	}
}
