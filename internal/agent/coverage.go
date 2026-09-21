package agent

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/observe"
)

// gap is one live tap whose saved policy is enforce and whose program is not on yet.
type gap struct {
	vm, tap string
}

// enforcingGaps lists live taps of enforcing VMs that do not carry the program.
// Those VMs are not protected: the caller must not treat the policy as applied.
func enforcingGaps(vms []identity.VM, modeOf func(string) string, attached map[string]bool, live func(string) bool) []gap {
	var out []gap
	for _, vm := range vms {
		if modeOf(vm.Name) != "enforce" {
			continue
		}
		for _, tap := range vm.Taps {
			if !live(tap) || attached[tap] {
				continue
			}
			out = append(out, gap{vm: vm.Name, tap: tap})
		}
	}
	return out
}

// quarantineTaps are attached taps whose saved mode is enforce and whose kernel
// mode is not enforce yet. Quarantine is optional and stays off unless asked.
func quarantineTaps(vms []identity.VM, savedOf func(string) string, kernelOf func(vm, tap string) string, attached map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, vm := range vms {
		if savedOf(vm.Name) != "enforce" {
			continue
		}
		for _, tap := range vm.Taps {
			if !attached[tap] || kernelOf(vm.Name, tap) == "enforce" || seen[tap] {
				continue
			}
			seen[tap] = true
			out = append(out, tap)
		}
	}
	return out
}

func linkUp(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (a *Agent) noteSeen(now time.Time, vms []identity.VM) {
	if a.seen == nil {
		a.seen = map[string]time.Time{}
	}
	if a.covered == nil {
		a.covered = map[string]bool{}
	}
	for _, vm := range vms {
		for _, tap := range vm.Taps {
			if a.covered[tap] {
				continue
			}
			if _, ok := a.seen[tap]; ok {
				continue
			}
			if !linkUp(tap) {
				continue
			}
			a.seen[tap] = now
		}
	}
}

func (a *Agent) attachedSet() map[string]bool {
	m := map[string]bool{}
	for _, n := range observe.AttachedTaps() {
		m[n] = true
	}
	return m
}

func (a *Agent) savedMode(vm string) string {
	pv := a.State.Policy()
	if pv == nil {
		return ""
	}
	row, ok := pv.Get(vm)
	if !ok {
		return ""
	}
	return row.Mode
}

func (a *Agent) kernelMode(vm, tap string) string {
	pv := a.State.Policy()
	if pv == nil {
		return ""
	}
	row, ok := pv.Get(vm)
	if !ok {
		return ""
	}
	for _, t := range row.Taps {
		if t.Tap == tap {
			return t.Kernel
		}
	}
	return ""
}

func (a *Agent) holdUncovered(vms []identity.VM) {
	for _, tap := range quarantineTaps(vms, a.savedMode, a.kernelMode, a.attachedSet()) {
		if err := observe.QuarantineTap(tap); err != nil {
			log.Printf("tap quarantine %s: %v", tap, err)
		}
	}
}

func (a *Agent) reportUncovered(now time.Time, vms []identity.VM) {
	cfg := a.cfg.Load()
	for _, g := range enforcingGaps(vms, a.savedMode, a.attachedSet(), linkUp) {
		var joined identity.VM
		for _, vm := range vms {
			if vm.Name == g.vm {
				joined = vm
			}
		}
		a.raise(now, cfg, "tap-uncovered|"+g.vm+"|"+g.tap, event.Event{
			Kind: event.KindDetection, TS: now, TGID: identity.PID32(joined.PID),
			VM:       event.VM{Name: joined.Name, UUID: joined.UUID, Runtime: joined.Runtime},
			Iface:    g.tap,
			Rule:     "tap-uncovered",
			Severity: "high",
			Message:  fmt.Sprintf("%s has %s up and its enforcing policy is not on that tap", g.vm, g.tap),
		})
	}
}

func (a *Agent) recordAttach(now time.Time, vms []identity.VM) {
	if a.covered == nil {
		a.covered = map[string]bool{}
	}
	attached := a.attachedSet()
	for _, vm := range vms {
		for _, tap := range vm.Taps {
			ready := attached[tap]
			if ready && a.savedMode(vm.Name) == "enforce" && a.kernelMode(vm.Name, tap) != "enforce" {
				ready = false
			}
			if !ready {
				if a.covered[tap] {
					a.covered[tap] = false
					if linkUp(tap) {
						a.seen[tap] = now
					}
				}
				continue
			}
			if start, ok := a.seen[tap]; ok {
				a.State.NoteTapAttach(vm.Name, now.Sub(start))
				delete(a.seen, tap)
			}
			a.covered[tap] = true
		}
	}
}
