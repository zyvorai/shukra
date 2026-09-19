package state

import (
	"fmt"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/identity"
)

// Enforcer puts isolation on a VM's tap interfaces. Isolation is recorded as
// applied only after an Enforcer says it took effect.
type Enforcer interface {
	// Available says whether isolation can be enforced, and if not, why.
	Available() (ok bool, reason string)
	// AllowList is the management networks an isolated VM can still reach.
	AllowList() []string
	Isolated(tap string) bool
	// Isolate and Release return the taps they changed, and an error naming any they could not.
	Isolate(taps []string) ([]string, error)
	Release(taps []string) ([]string, error)
}

// TapStat is one tap interface's traffic from the guest's point of view.
type TapStat struct {
	Name                      string
	FromPkts, FromBytes       uint64
	ToPkts, ToBytes           uint64
	DroppedPkts, DroppedBytes uint64
	Isolated                  bool
}

// TapRow is a TapStat joined to the VM that owns the tap.
type TapRow struct {
	VM           string `json:"vm"`
	Tap          string `json:"tap"`
	FromPkts     uint64 `json:"fromGuestPackets"`
	FromBytes    uint64 `json:"fromGuestBytes"`
	ToPkts       uint64 `json:"toGuestPackets"`
	ToBytes      uint64 `json:"toGuestBytes"`
	DroppedPkts  uint64 `json:"droppedPackets"`
	DroppedBytes uint64 `json:"droppedBytes"`
	Isolated     bool   `json:"isolated"`
}

// SetEnforcer sets what carries out isolation. Without one, isolate is recorded and nothing more.
func (s *State) SetEnforcer(e Enforcer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforcer = e
}

// SetTapSource sets where per-tap counters come from.
func (s *State) SetTapSource(fn func() []TapStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tapSource = fn
}

// Taps is the per-tap traffic for the VMs that own the taps, optionally for one VM.
func (s *State) Taps(vm string) []TapRow {
	s.mu.RLock()
	src, vms := s.tapSource, append([]identity.VM(nil), s.vms...)
	s.mu.RUnlock()
	if src == nil {
		return nil
	}
	owner := map[string]string{}
	for _, v := range vms {
		for _, t := range v.Taps {
			owner[t] = v.Name
		}
	}
	var out []TapRow
	for _, t := range src() {
		name, ok := owner[t.Name]
		if !ok || (vm != "" && name != vm) {
			continue
		}
		out = append(out, TapRow{
			VM: name, Tap: t.Name, FromPkts: t.FromPkts, FromBytes: t.FromBytes, ToPkts: t.ToPkts, ToBytes: t.ToBytes,
			DroppedPkts: t.DroppedPkts, DroppedBytes: t.DroppedBytes, Isolated: t.Isolated,
		})
	}
	return out
}

// Enforcement says how isolation is enforced: "tcx" when it can be, and
// "not_attached" otherwise with the reason.
func (s *State) Enforcement() (mode string, allow []string, reason string) {
	s.mu.RLock()
	e := s.enforcer
	s.mu.RUnlock()
	if e == nil {
		return "not_attached", nil, "TC/TCX tap enforcement is not in this build. No program was attached."
	}
	ok, why := e.Available()
	if !ok {
		return "not_attached", e.AllowList(), why
	}
	return "tcx", e.AllowList(), ""
}

// Isolate asks for the VM's taps to be isolated and records the outcome.
func (s *State) Isolate(vm, actor string) Isolation { return s.act("isolate", vm, actor) }

// Release lifts an isolation and records the outcome.
func (s *State) Release(vm, actor string) Isolation { return s.act("release", vm, actor) }

func (s *State) act(action, vmName, actor string) Isolation {
	rec := Isolation{
		VM: vmName, Enforcement: "not_attached",
		Audit: Audit{TS: time.Now().UTC(), Actor: actor, Action: action, VM: vmName, Result: "recorded_only"},
	}
	s.mu.RLock()
	enf := s.enforcer
	var vm identity.VM
	found := false
	for _, v := range s.vms {
		if v.Name == vmName {
			vm, found = v, true
			break
		}
	}
	s.mu.RUnlock()

	refuse := func(reason string) {
		rec.Reason, rec.Audit.Result = reason, "refused"
	}
	switch {
	case enf == nil:
		rec.Reason = "TC/TCX tap enforcement is not in this build. No program was attached."
	default:
		if ok, why := enf.Available(); !ok {
			refuse(why)
		} else if !found {
			refuse("no VM with that name is in the current scan")
		} else if len(vm.Taps) == 0 {
			refuse("the VM has no tap interface (user-mode networking has none), so there is nothing to enforce on")
		} else {
			rec.Taps = vm.Taps
			var done []string
			var err error
			verb := "isolated"
			if action == "isolate" {
				done, err = enf.Isolate(vm.Taps)
			} else {
				done, err = enf.Release(vm.Taps)
				verb = "released"
			}
			switch {
			case err == nil && len(done) == len(vm.Taps):
				rec.Applied, rec.Enforcement, rec.Audit.Result = true, "tcx", "applied"
				if action == "isolate" {
					rec.Reason = "Traffic to and from " + strings.Join(done, ", ") + " is dropped, except ARP, IPv6 neighbour discovery and " + strings.Join(enf.AllowList(), ", ") + ". This holds while shukrad runs: it is re-applied after a restart, but the tap is open while the daemon is down."
				} else {
					rec.Reason = "Isolation lifted on " + strings.Join(done, ", ") + "."
				}
			case len(done) == 0:
				rec.Enforcement, rec.Audit.Result = "tcx", "failed"
				rec.Reason = fmt.Sprintf("nothing was %s: %v", verb, err)
			default:
				// Some taps changed and some did not. Say so, and keep what took effect: a
				// half-isolated VM is safer left contained than silently reopened.
				rec.Enforcement, rec.Audit.Result = "tcx", "partial"
				rec.Reason = fmt.Sprintf("%s %d of %d taps (%s): %v", verb, len(done), len(vm.Taps), strings.Join(done, ", "), err)
			}
		}
	}

	s.mu.Lock()
	s.isolations = append(s.isolations, rec)
	if len(s.isolations) > MaxEvents {
		s.isolations = append([]Isolation(nil), s.isolations[len(s.isolations)-MaxEvents:]...)
	}
	p := s.persist
	s.mu.Unlock()
	if p != nil {
		p.Isolation(rec)
	}
	return rec
}

// ActiveIsolations is the VMs whose latest recorded action took effect as an
// isolation. A request that was refused, or only recorded, is not active.
func (s *State) ActiveIsolations() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	last := map[string]Audit{}
	for _, iso := range s.isolations {
		last[iso.VM] = iso.Audit
	}
	var out []string
	for vm, a := range last {
		if a.Action == "isolate" && (a.Result == "applied" || a.Result == "partial") {
			out = append(out, vm)
		}
	}
	return out
}

// ReapplyIsolations makes the kernel state match the recorded isolations. It
// covers a daemon restart, a VM that came back with a new tap, and a tap that
// appeared after the request. It records nothing and returns the VMs it acted on.
func (s *State) ReapplyIsolations() []string {
	s.mu.RLock()
	enf := s.enforcer
	vms := append([]identity.VM(nil), s.vms...)
	s.mu.RUnlock()
	if enf == nil {
		return nil
	}
	if ok, _ := enf.Available(); !ok {
		return nil
	}
	active := map[string]bool{}
	for _, v := range s.ActiveIsolations() {
		active[v] = true
	}
	var acted []string
	for _, vm := range vms {
		if !active[vm.Name] {
			continue
		}
		var pending []string
		for _, t := range vm.Taps {
			if !enf.Isolated(t) {
				pending = append(pending, t)
			}
		}
		if len(pending) == 0 {
			continue
		}
		if done, _ := enf.Isolate(pending); len(done) > 0 {
			acted = append(acted, vm.Name)
		}
	}
	return acted
}
