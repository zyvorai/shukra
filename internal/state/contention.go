package state

import (
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
)

// A vCPU that is preempted has an answer to "by whom", and when the answer is another VM the interesting
// question is the other way round too: what was that VM doing? Contention puts every VM's preemption and
// every culprit's own activity side by side, over the same window, so a noisy neighbour is one row to read
// instead of a comparison across pages.

// ContentionPair is one VM's CPU being taken by one other VM.
type ContentionPair struct {
	Victim      string  `json:"victim"`
	Culprit     string  `json:"culprit"`
	PreemptedNs uint64  `json:"preemptedNs"`
	Share       float64 `json:"share"` // of everything that preempted the victim's vCPUs, 0 to 1
}

// ContentionVictim is one VM whose vCPUs were preempted, and by whom, in three parts: other VMs, its own
// other threads (an iothread, another vCPU), and host tasks.
type ContentionVictim struct {
	VM             string                `json:"vm"`
	PreemptedNs    uint64                `json:"preemptedNs"`
	PreemptedCount uint64                `json:"preemptions"`
	ByOtherVMsNs   uint64                `json:"byOtherVmsNs"`
	BySelfNs       uint64                `json:"bySelfNs"`
	ByHostNs       uint64                `json:"byHostNs"`
	HostTasks      []aggregate.Preemptor `json:"topHostTasks"`
}

// ContentionCulprit is one VM that took CPU from others, and what it was doing meanwhile.
type ContentionCulprit struct {
	VM      string `json:"vm"`
	TookNs  uint64 `json:"tookNs"`
	Victims int    `json:"victims"`
	// OnCPUNs and Exits are the culprit's own activity over the same window: a culprit that is busy is
	// doing it to itself; one that is nearly idle is being scheduled badly.
	OnCPUNs uint64 `json:"onCpuNs"`
	Exits   uint64 `json:"exits"`
}

// Contention is the whole picture over one window.
type Contention struct {
	Window   string              `json:"window"`
	Pairs    []ContentionPair    `json:"pairs"`
	Victims  []ContentionVictim  `json:"victims"`
	Culprits []ContentionCulprit `json:"culprits"`
}

// Contention builds the picture over roughly the last window, or over the daemon's lifetime where there is
// not enough history yet, and says which. vm narrows it to that VM as the victim. A VM the sched program has
// not measured has no row, and a VM nothing preempted has a victim row of zero, which is a measurement.
func (s *State) Contention(vm string, now time.Time, window time.Duration) Contention {
	out := Contention{Window: "lifetime", Pairs: []ContentionPair{}, Victims: []ContentionVictim{}, Culprits: []ContentionCulprit{}}
	vendor := s.cpuVendorLocked()
	type activity struct{ onCPU, exits uint64 }
	act := map[string]activity{}
	sched := map[string]aggregate.SchedRow{}
	for _, v := range s.VMs() {
		life := s.Sched(v.Name)
		if len(life) == 0 || !life[0].Measured {
			continue
		}
		row := life[0]
		var exits uint64
		if k := s.KVM(v.Name); len(k) > 0 {
			exits = k[0].Exits
		}
		if per, span, ok := s.windowedInputs(v, now, window); ok {
			rows := windowRows(v, per, vendor)
			if len(rows.sched) > 0 {
				row = rows.sched[0]
			}
			if len(rows.kvm) > 0 {
				exits = rows.kvm[0].Exits
			}
			out.Window = span.Round(time.Second).String()
		}
		sched[v.Name] = row
		act[v.Name] = activity{onCPU: row.OnCPUNs, exits: exits}
	}

	took := map[string]uint64{}
	victims := map[string]map[string]bool{}
	for name, row := range sched {
		if vm != "" && name != vm {
			continue
		}
		v := ContentionVictim{VM: name, PreemptedNs: row.PreemptedNs, PreemptedCount: row.PreemptedCount, HostTasks: []aggregate.Preemptor{}}
		for _, p := range row.AllPreemptors {
			who, isVM := strings.CutPrefix(p.Who, aggregate.VMLabel)
			switch {
			case isVM && who == name:
				v.BySelfNs += p.Ns
			case isVM:
				v.ByOtherVMsNs += p.Ns
				took[who] += p.Ns
				if victims[who] == nil {
					victims[who] = map[string]bool{}
				}
				victims[who][name] = true
				share := 0.0
				if row.PreemptedNs > 0 {
					share = float64(p.Ns) / float64(row.PreemptedNs)
				}
				out.Pairs = append(out.Pairs, ContentionPair{Victim: name, Culprit: who, PreemptedNs: p.Ns, Share: share})
			default:
				v.ByHostNs += p.Ns
				v.HostTasks = append(v.HostTasks, p)
			}
		}
		if len(v.HostTasks) > 5 {
			v.HostTasks = v.HostTasks[:5]
		}
		out.Victims = append(out.Victims, v)
	}
	for who, ns := range took {
		a := act[who]
		out.Culprits = append(out.Culprits, ContentionCulprit{VM: who, TookNs: ns, Victims: len(victims[who]), OnCPUNs: a.onCPU, Exits: a.exits})
	}
	sort.Slice(out.Pairs, func(i, j int) bool {
		a, b := out.Pairs[i], out.Pairs[j]
		if a.PreemptedNs != b.PreemptedNs {
			return a.PreemptedNs > b.PreemptedNs
		}
		return a.Victim+"\x00"+a.Culprit < b.Victim+"\x00"+b.Culprit
	})
	sort.Slice(out.Victims, func(i, j int) bool {
		if out.Victims[i].PreemptedNs != out.Victims[j].PreemptedNs {
			return out.Victims[i].PreemptedNs > out.Victims[j].PreemptedNs
		}
		return out.Victims[i].VM < out.Victims[j].VM
	})
	sort.Slice(out.Culprits, func(i, j int) bool {
		if out.Culprits[i].TookNs != out.Culprits[j].TookNs {
			return out.Culprits[i].TookNs > out.Culprits[j].TookNs
		}
		return out.Culprits[i].VM < out.Culprits[j].VM
	})
	return out
}
