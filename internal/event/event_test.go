package event

import "testing"

func TestGuestAttributionNeedsATapAndANamedVM(t *testing.T) {
	cases := []struct {
		name  string
		in    Event
		guest bool
		attr  string
	}{
		{"seen on a tap, VM known", Event{Kind: KindGuestConnect, Attribution: AttributionGuestTap, VM: VM{Name: "db"}}, true, AttributionGuestTap},
		{"a detection derived from it", Event{Kind: KindDetection, Attribution: AttributionGuestTap, VM: VM{Name: "db"}}, true, AttributionGuestTap},
		{"claims the tap but no VM owns it", Event{Kind: KindGuestConnect, Attribution: AttributionGuestTap}, false, AttributionUnattributed},
		{"a host connect from QEMU", Event{Kind: KindTCPConnect, VM: VM{Name: "db"}}, false, AttributionQEMU},
		{"a host connect claiming guest attribution", Event{Kind: KindTCPConnect, GuestAttributed: true, VM: VM{Name: "db"}}, false, AttributionQEMU},
		{"a made-up attribution string", Event{Kind: KindTCPConnect, Attribution: "guest", GuestAttributed: true, VM: VM{Name: "db"}}, false, AttributionQEMU},
		{"no VM, no attribution", Event{Kind: KindExec}, false, AttributionUnattributed},
	}
	for _, c := range cases {
		e := c.in
		Normalize(&e)
		if e.GuestAttributed != c.guest || e.Attribution != c.attr || e.Product != "shukra" {
			t.Errorf("%s: guest=%v attribution=%q, want %v %q", c.name, e.GuestAttributed, e.Attribution, c.guest, c.attr)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	e := Event{Kind: KindGuestConnect, Attribution: AttributionGuestTap, VM: VM{Name: "db"}}
	Normalize(&e)
	first := e
	Normalize(&e)
	if e != first {
		t.Fatalf("%+v then %+v", first, e)
	}
}
