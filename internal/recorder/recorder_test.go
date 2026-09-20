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

func TestSnapshotRoundTrip(t *testing.T) {
	r := New(3)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		r.Add(event.Event{Kind: event.KindExec, TS: now.Add(time.Duration(i) * time.Second), VM: event.VM{Name: "b"}, PID: uint32(i)})
	}
	r.Add(event.Event{Kind: event.KindExec, TS: now, VM: event.VM{Name: "a"}, PID: 99})
	r.Add(event.Event{Kind: event.KindExec, TS: now, PID: 7}) // host rollup

	snap := r.Snapshot()
	if len(snap) != 5 { // b keeps 3 (cap), a 1, _host 1
		t.Fatalf("%d events: %+v", len(snap), snap)
	}
	if snap[0].Attribution != event.AttributionUnattributed || snap[1].VM.Name != "a" || snap[2].PID != 2 || snap[4].PID != 4 {
		t.Fatalf("order: %+v", snap)
	}
	again := New(3)
	for _, e := range snap {
		again.Add(e)
	}
	if got := again.Window("b", time.Minute, now.Add(10*time.Second)); len(got) != 3 || got[0].PID != 2 {
		t.Fatalf("%+v", got)
	}
}

func pids(evs []event.Event) []uint32 {
	var out []uint32
	for _, e := range evs {
		out = append(out, e.PID)
	}
	return out
}

func same(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A full ring overwrites in place, so where the oldest event sits moves round the array. Whatever the
// position, what comes back is the newest cap events, oldest first.
func TestOrderHoldsAcrossEveryPositionOfAWrappedRing(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	for _, n := range []int{1, 3, 4, 5, 7, 8, 9, 11, 12, 13, 41} {
		r := New(4)
		for i := 0; i < n; i++ {
			r.Add(event.Event{Kind: event.KindExec, TS: base.Add(time.Duration(i) * time.Second), VM: event.VM{Name: "a"}, PID: uint32(i)})
		}
		var want []uint32
		for i := max(0, n-4); i < n; i++ {
			want = append(want, uint32(i))
		}
		if got := pids(r.Window("a", time.Hour, base.Add(time.Hour))); !same(got, want) {
			t.Fatalf("%d added: window %v, want %v", n, got, want)
		}
		if got := pids(r.Snapshot()); !same(got, want) {
			t.Fatalf("%d added: snapshot %v, want %v", n, got, want)
		}
	}
}

func TestTheWindowCutsAWrappedRingByTimeAndKeepsItsOrder(t *testing.T) {
	base := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	r := New(4)
	for i := 0; i < 10; i++ { // holds 6, 7, 8, 9 at 6 to 9 seconds
		r.Add(event.Event{Kind: event.KindExec, TS: base.Add(time.Duration(i) * time.Second), VM: event.VM{Name: "a"}, PID: uint32(i)})
	}
	now := base.Add(9 * time.Second)
	if got := pids(r.Window("a", 2*time.Second, now)); !same(got, []uint32{7, 8, 9}) {
		t.Fatalf("%v", got)
	}
	if got := r.Window("a", time.Second, now.Add(time.Hour)); got != nil {
		t.Fatalf("nothing in the window is nil, which the caller tests for: %#v", got)
	}
	if got := r.Window("nobody", time.Hour, now); got != nil {
		t.Fatalf("an unknown VM is nil: %#v", got)
	}
}

func TestOneVMFillingItsRingNeverEvictsAnothers(t *testing.T) {
	now := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	r := New(3)
	r.Add(event.Event{Kind: event.KindExec, TS: now, VM: event.VM{Name: "quiet"}, PID: 1})
	for i := 0; i < 50; i++ {
		r.Add(event.Event{Kind: event.KindExec, TS: now, VM: event.VM{Name: "busy"}, PID: uint32(100 + i)})
	}
	if got := pids(r.Window("quiet", time.Hour, now)); !same(got, []uint32{1}) {
		t.Fatalf("%v", got)
	}
	if got := pids(r.Window("busy", time.Hour, now)); !same(got, []uint32{147, 148, 149}) {
		t.Fatalf("%v", got)
	}
	for _, all := range []string{"", "_"} {
		if got := r.Window(all, time.Hour, now); len(got) != 4 {
			t.Fatalf("%q: %d events across VMs", all, len(got))
		}
	}
}

// Adding to a full ring must not allocate: a host that produces hundreds of events a second was spending most
// of the daemon's CPU in the garbage collector because every add copied the whole ring into a new slice.
func TestAddingToAFullRingDoesNotAllocate(t *testing.T) {
	r := New(DefaultCap)
	e := event.Event{Kind: event.KindGuestTLS, TS: time.Now().UTC(), VM: event.VM{Name: "web"}, SNI: "example.com", Dst: "203.0.113.9"}
	for i := 0; i < DefaultCap+10; i++ {
		r.Add(e)
	}
	if n := testing.AllocsPerRun(2000, func() { r.Add(e) }); n != 0 {
		t.Fatalf("%v allocations per add to a full ring", n)
	}
}
