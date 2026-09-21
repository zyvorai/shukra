package agent

import (
	"fmt"
	"strings"

	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
)

type netlinkLinkState struct {
	MTU         uint32
	OperState   string
	MasterIndex int32
}

type netlinkFinding struct {
	rule     string
	severity string
	message  string
	key      string
}

// ingestNetlink stores the raw kernel fact, joins direct tap changes to the VM
// that owns the interface, and raises a small set of evidence-backed findings.
// Attribution stays host-netlink: owning the tap does not prove the guest made
// the control-plane change.
func (a *Agent) ingestNetlink(e event.Event, cfg *detect.Config) {
	if e.Netlink == nil {
		return
	}
	vm, found := vmForInterface(a.State.VMs(), e.Netlink.Interface)
	if found {
		e.VM = event.VM{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime}
	}
	event.Normalize(&e)
	a.State.AddEvent(e)

	previous, hadPrevious := a.updateNetlinkState(e)
	f, ok := classifyNetlink(e, found, previous, hadPrevious)
	if !ok {
		return
	}
	detection := e
	detection.Kind = event.KindDetection
	detection.Rule = f.rule
	detection.Severity = f.severity
	detection.Message = f.message
	a.raise(e.TS, cfg, f.key, detection)
}

func vmForInterface(vms []identity.VM, iface string) (identity.VM, bool) {
	if iface == "" {
		return identity.VM{}, false
	}
	for _, vm := range vms {
		for _, tap := range vm.Taps {
			if tap == iface {
				return vm, true
			}
		}
	}
	return identity.VM{}, false
}

func (a *Agent) updateNetlinkState(e event.Event) (netlinkLinkState, bool) {
	if e.Kind != event.KindNetlinkLink || e.Netlink == nil || e.Netlink.IfIndex <= 0 {
		return netlinkLinkState{}, false
	}
	a.netlinkMu.Lock()
	defer a.netlinkMu.Unlock()
	previous, ok := a.netlinks[e.Netlink.IfIndex]
	if e.Netlink.Action == "delete" {
		delete(a.netlinks, e.Netlink.IfIndex)
	} else {
		a.netlinks[e.Netlink.IfIndex] = netlinkLinkState{
			MTU: e.Netlink.MTU, OperState: e.Netlink.OperState, MasterIndex: e.Netlink.MasterIndex,
		}
	}
	return previous, ok
}

func classifyNetlink(e event.Event, ownsInterface bool, previous netlinkLinkState, hadPrevious bool) (netlinkFinding, bool) {
	n := e.Netlink
	if n == nil {
		return netlinkFinding{}, false
	}
	iface := n.Interface
	if iface == "" {
		iface = fmt.Sprintf("ifindex %d", n.IfIndex)
	}
	keySuffix := fmt.Sprintf("%s|%d", n.Interface, n.IfIndex)
	switch e.Kind {
	case event.KindNetlinkError:
		return netlinkFinding{
			rule: "netlink-overrun", severity: "high", key: "netlink-overrun",
			message: fmt.Sprintf("kernel Netlink observation lost messages or returned error %d; network-change history may be incomplete", n.Error),
		}, true
	case event.KindNetlinkRoute:
		if n.Action == "delete" && (n.Destination == "0.0.0.0/0" || n.Destination == "::/0") {
			return netlinkFinding{
				rule: "default-route-removed", severity: "high",
				key: "netlink-default-route-removed|" + n.Family + "|" + fmt.Sprint(n.Table),
				message: fmt.Sprintf("kernel removed the %s default route from table %d via %s", n.Family, n.Table, iface),
			}, true
		}
	case event.KindNetlinkNeighbor:
		if strings.Contains(n.State, "failed") {
			return netlinkFinding{
				rule: "neighbor-failed", severity: "medium",
				key: "netlink-neighbor-failed|" + keySuffix + "|" + n.Address,
				message: fmt.Sprintf("neighbor resolution failed for %s on %s", n.Address, iface),
			}, true
		}
	case event.KindNetlinkAddress:
		if ownsInterface && n.Action == "delete" {
			return netlinkFinding{
				rule: "tap-address-removed", severity: "medium",
				key: "netlink-tap-address-removed|" + keySuffix + "|" + n.Address,
				message: fmt.Sprintf("address %s/%d was removed from VM interface %s", n.Address, n.PrefixLen, iface),
			}, true
		}
	case event.KindNetlinkLink:
		if !ownsInterface {
			return netlinkFinding{}, false
		}
		if n.Action == "delete" {
			return netlinkFinding{
				rule: "tap-link-deleted", severity: "high", key: "netlink-tap-deleted|" + keySuffix,
				message: fmt.Sprintf("VM interface %s was deleted from the host", iface),
			}, true
		}
		if n.OperState == "down" || n.OperState == "lower-layer-down" {
			return netlinkFinding{
				rule: "tap-link-down", severity: "high", key: "netlink-tap-down|" + keySuffix,
				message: fmt.Sprintf("VM interface %s changed to %s", iface, n.OperState),
			}, true
		}
		if hadPrevious && previous.MTU != 0 && n.MTU != 0 && previous.MTU != n.MTU {
			return netlinkFinding{
				rule: "tap-mtu-changed", severity: "medium", key: "netlink-tap-mtu|" + keySuffix,
				message: fmt.Sprintf("VM interface %s MTU changed from %d to %d", iface, previous.MTU, n.MTU),
			}, true
		}
		if hadPrevious && previous.MasterIndex != n.MasterIndex {
			return netlinkFinding{
				rule: "tap-master-changed", severity: "high", key: "netlink-tap-master|" + keySuffix,
				message: fmt.Sprintf("VM interface %s master changed from ifindex %d to %d", iface, previous.MasterIndex, n.MasterIndex),
			}, true
		}
	}
	return netlinkFinding{}, false
}
