package agent

import (
	"testing"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
)

func netlinkEvent(kind event.Kind, n event.Netlink) event.Event {
	return event.Event{Kind: kind, Netlink: &n, Attribution: event.AttributionHostNetlink}
}

func TestVMForInterface(t *testing.T) {
	vms := []identity.VM{{Name: "payments", Taps: []string{"tap7"}}}
	vm, ok := vmForInterface(vms, "tap7")
	if !ok || vm.Name != "payments" {
		t.Fatalf("got %#v, %v", vm, ok)
	}
	if _, ok := vmForInterface(vms, "eth0"); ok {
		t.Fatal("host interface attributed to a VM")
	}
}

func TestClassifyDeletedVMTap(t *testing.T) {
	e := netlinkEvent(event.KindNetlinkLink, event.Netlink{Action: "delete", Interface: "tap7", IfIndex: 7})
	f, ok := classifyNetlink(e, true, netlinkLinkState{}, false)
	if !ok || f.rule != "tap-link-deleted" || f.severity != "high" {
		t.Fatalf("unexpected finding: %#v, %v", f, ok)
	}
}

func TestClassifyMTUChangeNeedsPreviousValue(t *testing.T) {
	e := netlinkEvent(event.KindNetlinkLink, event.Netlink{Action: "new", Interface: "tap7", IfIndex: 7, MTU: 9000, OperState: "up"})
	if _, ok := classifyNetlink(e, true, netlinkLinkState{}, false); ok {
		t.Fatal("first observation reported as a change")
	}
	f, ok := classifyNetlink(e, true, netlinkLinkState{MTU: 1500, OperState: "up"}, true)
	if !ok || f.rule != "tap-mtu-changed" || f.message != "VM interface tap7 MTU changed from 1500 to 9000" {
		t.Fatalf("unexpected finding: %#v, %v", f, ok)
	}
}

func TestClassifyDefaultRouteRemoval(t *testing.T) {
	e := netlinkEvent(event.KindNetlinkRoute, event.Netlink{Action: "delete", Family: "ipv4", Destination: "0.0.0.0/0", Table: 254, Interface: "bond0"})
	f, ok := classifyNetlink(e, false, netlinkLinkState{}, false)
	if !ok || f.rule != "default-route-removed" || f.severity != "high" {
		t.Fatalf("unexpected finding: %#v, %v", f, ok)
	}
}

func TestClassifyFailedNeighbor(t *testing.T) {
	e := netlinkEvent(event.KindNetlinkNeighbor, event.Netlink{Action: "new", Interface: "br0", IfIndex: 3, Address: "192.0.2.1", State: "failed"})
	f, ok := classifyNetlink(e, false, netlinkLinkState{}, false)
	if !ok || f.rule != "neighbor-failed" || f.severity != "medium" {
		t.Fatalf("unexpected finding: %#v, %v", f, ok)
	}
}

func TestClassifyIgnoresHostLinkDown(t *testing.T) {
	e := netlinkEvent(event.KindNetlinkLink, event.Netlink{Action: "new", Interface: "eth0", IfIndex: 2, OperState: "down"})
	if _, ok := classifyNetlink(e, false, netlinkLinkState{}, false); ok {
		t.Fatal("host link was treated as a VM tap")
	}
}
