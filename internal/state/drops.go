package state

import (
	"sort"
	"time"

	"github.com/zyvorai/shukra/internal/identity"
)

// dropFloor is how many unexplained drops it takes to say something. The tap program's counters
// and the kernel's drop counts are read a moment apart, so a difference of a few packets is skew
// between two reads, not another program dropping traffic.
const dropFloor = 5

// DropStat is what the kernel dropped on one tap for one reason, as skb:kfree_skb reported it.
type DropStat struct {
	Tap      string
	Reason   string
	Count    uint64
	Location string
}

// DropRow is one reason on one VM's tap.
type DropRow struct {
	VM       string `json:"vm"`
	Tap      string `json:"tap"`
	Reason   string `json:"reason"`
	Count    uint64 `json:"count"`
	Location string `json:"location,omitempty"`
}

// DropReason is a reason and how many packets it accounts for.
type DropReason struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

// DropTap says, for one VM's tap, how many packets the kernel dropped and whose drops they were.
// Shukra's own isolation drops appear in the kernel's count as TC_INGRESS or TC_EGRESS, so what
// the tap program says it dropped is subtracted, and so is a full tap queue, which is the guest not
// reading its NIC and is reported on its own (QueueFull). What is left, OtherDrops, is something else.
type DropTap struct {
	VM            string       `json:"vm"`
	Tap           string       `json:"tap"`
	KernelDrops   uint64       `json:"kernelDrops"`
	ShukraDropped uint64       `json:"shukraDropped"`
	OtherDrops    uint64       `json:"otherDrops"`
	QueueFull     uint64       `json:"guestNotReading"`
	Reasons       []DropReason `json:"reasons"`
}

// dropSnap is one tap's drop counts at a moment: by reason, and what Shukra itself dropped.
type dropSnap struct {
	reasons map[string]uint64
	shukra  uint64
}

func isTC(reason string) bool { return reason == "TC_INGRESS" || reason == "TC_EGRESS" }

// DropsMeasured says whether the drops program is measuring, so a page can say "not measuring" and not show an empty table.
func (s *State) DropsMeasured() bool { return s.dropsAttached() }

// SetDropSource sets where the kernel's per-tap drop counts come from.
func (s *State) SetDropSource(fn func() []DropStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropSource = fn
}

// dropsAttached says whether the drops program is measuring. Without it there is nothing to say
// about drops, and saying "none" would be inventing a zero.
func (s *State) dropsAttached() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.programs {
		if p.Name == "drops" {
			return p.Status == "attached"
		}
	}
	return false
}

// dropInputs reads the sources outside the lock, since they read kernel maps.
func (s *State) dropInputs() (vms []identity.VM, taps []TapStat, drops []DropStat, ok bool) {
	s.mu.RLock()
	tsrc, dsrc := s.tapSource, s.dropSource
	vms = append([]identity.VM(nil), s.vms...)
	s.mu.RUnlock()
	if dsrc == nil {
		return nil, nil, nil, false
	}
	if tsrc != nil {
		taps = tsrc()
	}
	return vms, taps, dsrc(), true
}

// snapsFrom is the drop counts per tap, with what Shukra itself dropped on it.
func snapsFrom(taps []TapStat, drops []DropStat) map[string]dropSnap {
	out := map[string]dropSnap{}
	for _, t := range taps {
		out[t.Name] = dropSnap{reasons: map[string]uint64{}, shukra: t.DroppedPkts}
	}
	for _, d := range drops {
		sn, ok := out[d.Tap]
		if !ok {
			sn = dropSnap{reasons: map[string]uint64{}}
		}
		sn.reasons[d.Reason] += d.Count
		out[d.Tap] = sn
	}
	return out
}

// joinTaps names the VM that owns each tap and works out whose drops they are. A tap no VM owns is
// left out: a name is never guessed.
func joinTaps(vms []identity.VM, snaps map[string]dropSnap, only string) []DropTap {
	owner := map[string]string{}
	for _, v := range vms {
		for _, t := range v.Taps {
			owner[t] = v.Name
		}
	}
	var out []DropTap
	for tap, sn := range snaps {
		name, ok := owner[tap]
		if !ok || (only != "" && name != only) {
			continue
		}
		var total, tc uint64
		reasons := []DropReason{} // [] and not null, so a client can loop over a tap with no drops
		for r, n := range sn.reasons {
			if n == 0 {
				continue
			}
			total += n
			if isTC(r) {
				tc += n
			}
			reasons = append(reasons, DropReason{Reason: r, Count: n})
		}
		sort.Slice(reasons, func(i, j int) bool {
			if reasons[i].Count != reasons[j].Count {
				return reasons[i].Count > reasons[j].Count
			}
			return reasons[i].Reason < reasons[j].Reason
		})
		// What Shukra dropped is inside the TC count, so it can explain at most that much.
		explained := min(sn.shukra, tc)
		full := sn.reasons["FULL_RING"]
		other := total - explained
		other -= min(other, full)
		out = append(out, DropTap{
			VM: name, Tap: tap, KernelDrops: total, ShukraDropped: sn.shukra, OtherDrops: other,
			QueueFull: full, Reasons: reasons,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VM != out[j].VM {
			return out[i].VM < out[j].VM
		}
		return out[i].Tap < out[j].Tap
	})
	return out
}

// Drops is what the kernel dropped on the taps of the VMs that own them, optionally for one VM:
// one row per reason, and a per-tap summary that says how much of it Shukra did itself.
func (s *State) Drops(vm string) ([]DropRow, []DropTap) {
	vms, taps, drops, ok := s.dropInputs()
	if !ok || !s.dropsAttached() {
		return nil, nil
	}
	owner := map[string]string{}
	for _, v := range vms {
		for _, t := range v.Taps {
			owner[t] = v.Name
		}
	}
	var rows []DropRow
	for _, d := range drops {
		name, owned := owner[d.Tap]
		if !owned || (vm != "" && name != vm) {
			continue
		}
		rows = append(rows, DropRow{VM: name, Tap: d.Tap, Reason: d.Reason, Count: d.Count, Location: d.Location})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].VM != rows[j].VM {
			return rows[i].VM < rows[j].VM
		}
		if rows[i].Tap != rows[j].Tap {
			return rows[i].Tap < rows[j].Tap
		}
		return rows[i].Count > rows[j].Count
	})
	return rows, joinTaps(vms, snapsFrom(taps, drops), vm)
}

// DropTapsOver is the per-tap summary over roughly the last window, or over the daemon's lifetime
// when there is not enough history yet. over says which: a span, or "lifetime". Nothing when the
// drops program is not attached.
func (s *State) DropTapsOver(vm string, now time.Time, window time.Duration) (taps []DropTap, over string) {
	vms, tapStats, drops, ok := s.dropInputs()
	if !ok || !s.dropsAttached() {
		return nil, ""
	}
	cur := snapsFrom(tapStats, drops)
	base, span, ok := s.dropBase(now, window)
	if !ok {
		return joinTaps(vms, cur, vm), "lifetime"
	}
	return joinTaps(vms, subSnaps(cur, base), vm), span.Round(time.Second).String()
}

// subSnaps is cur - old, counter by counter. A counter that went backwards was reset, and is then
// read as everything since the reset rather than as a huge number.
func subSnaps(cur, old map[string]dropSnap) map[string]dropSnap {
	out := make(map[string]dropSnap, len(cur))
	for tap, c := range cur {
		o := old[tap]
		d := dropSnap{reasons: map[string]uint64{}, shukra: subOrAll(c.shukra, o.shukra)}
		for r, n := range c.reasons {
			d.reasons[r] = subOrAll(n, o.reasons[r])
		}
		out[tap] = d
	}
	return out
}

func subOrAll(cur, old uint64) uint64 {
	if cur < old {
		return cur
	}
	return cur - old
}

// ForeignDrops is, per VM, how many packets the kernel dropped on its taps that Shukra did not.
// The threshold rule guest_drops_per_sec reads it.
func (s *State) ForeignDrops() map[string]uint64 {
	vms, taps, drops, ok := s.dropInputs()
	if !ok || !s.dropsAttached() {
		return nil
	}
	out := map[string]uint64{}
	for _, t := range joinTaps(vms, snapsFrom(taps, drops), "") {
		out[t.VM] += t.OtherDrops
	}
	return out
}
