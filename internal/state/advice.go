package state

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
)

// The advisor answers "is this VM the right size?" from what the host already measures, in both directions:
// a VM that sits idle with more vCPUs than it uses, and a VM that wants CPU and is not getting it. It is advice
// to a person, never an action, and it says how sure it is and what it cannot see.
//
// Idleness is the time the vCPUs spent halted (HLT exits, which last as long as the guest was idle), over the
// window, as a share of what the vCPUs could have done. That is a lower bound on idleness: a guest that idles
// by polling (idle=poll) or that mostly runs work that never halts reads as busy. Exit reasons are only named
// on Intel hosts, so on another CPU idleness is "not available" and nothing about it is claimed.
const (
	adviceMinSpan = minSpan // less history than a windowed verdict stands on
	// DefaultAdviceWindow is how far back the advisor looks: idleness needs a longer view than a stall does.
	DefaultAdviceWindow = MaxExplainWindow

	overIdle     = 0.80 // idle at least this share of the window's capacity...
	overBusy     = 0.20 // ...and busy at most this share
	nearlyIdle   = 0.95
	starvedBusy  = 0.50 // busy at least this much and still waiting for a CPU
	starvedShare = 0.10 // of the time the vCPUs wanted to run, preempted
	starvedHigh  = 0.20
	starvedRQNs  = 2_000_000
	// unaccountedNote is the share of capacity that is neither halted nor busy above which no_change says so.
	unaccountedNote = 0.30
)

// Advice is one thing to consider for one VM.
type Advice struct {
	Kind       string   `json:"kind"`
	Confidence string   `json:"confidence"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence"`
}

// AdviceRow is one VM: the numbers, and what they suggest.
type AdviceRow struct {
	VM     string `json:"vm"`
	VCPUs  int    `json:"vcpus"`
	Window string `json:"window"`
	// IdleAvailable says whether halt time is named on this CPU. IdleFraction is meaningless without it.
	IdleAvailable bool `json:"idleAvailable"`
	// IdleFraction is halted time as a share (0 to 1) of what the vCPUs could have run for in the window.
	IdleFraction float64 `json:"idleFraction"`
	// BusyFraction is the vCPU threads' on-CPU time over the same capacity, and BusyVCPUs the same in vCPUs.
	BusyFraction float64 `json:"busyFraction"`
	BusyVCPUs    float64 `json:"busyVcpus"`
	PreemptShare float64 `json:"preemptShare"` // of the time the vCPUs wanted to run, preempted
	// UnaccountedFraction is the share of the vCPUs' capacity that was neither halted nor on a CPU. It is large
	// where vCPUs are offline in the guest or idle without HLT (MWAIT, a polling loop), and it is why idleness is a
	// lower bound. Only meaningful where IdleAvailable.
	UnaccountedFraction float64  `json:"unaccountedFraction"`
	RunqueueP99Ns       uint64   `json:"runqueueDelayP99Ns"`
	Advice              []Advice `json:"advice"`
}

// AdviceReport is the advisor's answer for one or every VM.
type AdviceReport struct {
	Window string      `json:"window"`
	Rows   []AdviceRow `json:"rows"`
}

// Advise looks at each VM over roughly the last window. A VM with too little history, no vCPU thread or no
// kernel measurement has a row that says so, and no advice: there is no zero to reason from.
func (s *State) Advise(vm string, now time.Time, window time.Duration) AdviceReport {
	if window <= 0 {
		window = DefaultAdviceWindow
	}
	rep := AdviceReport{Window: window.String(), Rows: []AdviceRow{}}
	vendor := s.cpuVendorLocked()
	for _, v := range s.VMs() {
		if vm != "" && v.Name != vm {
			continue
		}
		row := AdviceRow{VM: v.Name, Window: "none", Advice: []Advice{}}
		for _, t := range v.ThreadInfo {
			if t.Role == "vcpu" {
				row.VCPUs++
			}
		}
		life := s.Sched(v.Name)
		lifeKVM := s.KVM(v.Name)
		measured := len(life) > 0 && life[0].Measured && len(lifeKVM) > 0 && lifeKVM[0].Measured
		per, span, ok := s.windowedInputs(v, now, window)
		switch {
		case !measured:
			row.Advice = append(row.Advice, notEnough("The kvm and sched programs have not measured this VM, so nothing about its size can be said."))
		case row.VCPUs == 0:
			row.Advice = append(row.Advice, notEnough("No vCPU thread is known for this VM, so its size cannot be judged."))
		case !ok || span < adviceMinSpan:
			row.Advice = append(row.Advice, notEnough(fmt.Sprintf("Less than %s of history so far. Ask again shortly.", adviceMinSpan)))
		default:
			rows := windowRows(v, per, vendor)
			row.Window = span.Round(time.Second).String()
			if rep.Window == window.String() {
				rep.Window = row.Window
			}
			fillAdvice(&row, rows, span)
		}
		rep.Rows = append(rep.Rows, row)
	}
	sort.Slice(rep.Rows, func(i, j int) bool { return rep.Rows[i].VM < rep.Rows[j].VM })
	return rep
}

func notEnough(why string) Advice {
	return Advice{Kind: "not_enough_data", Confidence: "high", Summary: why, Evidence: []string{}}
}

// fillAdvice computes the numbers and the advice for one VM from its windowed rows.
func fillAdvice(row *AdviceRow, rows windowedRows, span time.Duration) {
	capacity := float64(span.Nanoseconds()) * float64(row.VCPUs)
	var vcpuOn, worstRQ uint64
	for _, t := range rows.threads {
		if t.Role != "vcpu" {
			continue
		}
		vcpuOn += t.OnCPUNs
		worstRQ = max(worstRQ, t.WakeupDelayP99Ns)
	}
	var preempt uint64
	if len(rows.sched) > 0 {
		preempt = rows.sched[0].PreemptedNs
	}
	row.RunqueueP99Ns = worstRQ
	row.BusyFraction = math.Min(1, float64(vcpuOn)/capacity)
	row.BusyVCPUs = row.BusyFraction * float64(row.VCPUs)
	if vcpuOn+preempt > 0 {
		row.PreemptShare = float64(preempt) / float64(vcpuOn+preempt)
	}
	if len(rows.kvm) > 0 {
		var halt uint64
		named := false
		for _, r := range rows.kvm[0].AllReasons {
			if r.Name != "" {
				named = true
			}
			if r.Name == "hlt" {
				halt += r.TotalNs
			}
		}
		row.IdleAvailable = named
		if named {
			row.IdleFraction = math.Min(1, float64(halt)/capacity)
			row.UnaccountedFraction = math.Max(0, 1-row.IdleFraction-row.BusyFraction)
		}
	}

	starved := row.BusyFraction >= starvedBusy && (row.PreemptShare >= starvedShare || worstRQ >= starvedRQNs)
	if starved {
		conf := "medium"
		if row.PreemptShare >= starvedHigh || worstRQ >= aggregate.SlowWakeupNS {
			conf = "high"
		}
		row.Advice = append(row.Advice, Advice{
			Kind: "starved", Confidence: conf,
			Summary: "This VM wants more CPU than the host gives it. Adding vCPUs would add more threads that wait: reduce what it competes with first (pin it, move a neighbour: see trace contention).",
			Evidence: []string{fmt.Sprintf("Its vCPUs ran %.0f%% of the window, were preempted for %.0f%% of the time they wanted to run, and the worst vCPU waited up to %s for a CPU after a wakeup.",
				100*row.BusyFraction, 100*row.PreemptShare, dur(worstRQ))},
		})
	}
	if !row.IdleAvailable {
		row.Advice = append(row.Advice, Advice{
			Kind: "idle_unavailable", Confidence: "high",
			Summary:  "Idleness cannot be measured on this CPU: KVM's exit reasons are only named on Intel hosts, so no claim is made about this VM being over-provisioned.",
			Evidence: []string{},
		})
		return
	}
	conf := "medium"
	if span < 3*time.Minute {
		conf = "low" // a short window is a short sample
	}
	suggest := int(math.Max(1, math.Ceil(row.BusyVCPUs*2)))
	switch {
	case !starved && row.VCPUs >= 2 && row.IdleFraction >= overIdle && row.BusyFraction <= overBusy && suggest < row.VCPUs:
		row.Advice = append(row.Advice, Advice{
			Kind: "overprovisioned", Confidence: conf,
			Summary: fmt.Sprintf("This VM has %d vCPUs and used about %.1f of them. %d would leave it twice the headroom it used. Fewer vCPUs also mean fewer threads competing for host CPUs.", row.VCPUs, row.BusyVCPUs, suggest),
			Evidence: []string{fmt.Sprintf("Over %s its vCPUs were halted %.0f%% of the time they could have run and on a CPU %.0f%%. Idleness is a lower bound: a guest that idles by polling reads as busy.",
				row.Window, 100*row.IdleFraction, 100*row.BusyFraction)},
		})
	case !starved && row.VCPUs == 1 && row.IdleFraction >= nearlyIdle:
		row.Advice = append(row.Advice, Advice{
			Kind: "nearly_idle", Confidence: conf,
			Summary:  "This VM's only vCPU was almost always halted. It is a candidate for consolidation onto a shared host if its workload allows.",
			Evidence: []string{fmt.Sprintf("Over %s its vCPU was halted %.0f%% of the time.", row.Window, 100*row.IdleFraction)},
		})
	}
	if len(row.Advice) == 0 {
		ev := []string{fmt.Sprintf("Over %s its vCPUs ran %.0f%% and were halted %.0f%% of their capacity, and were preempted for %.0f%% of the time they wanted to run.",
			row.Window, 100*row.BusyFraction, 100*row.IdleFraction, 100*row.PreemptShare)}
		if row.UnaccountedFraction >= unaccountedNote {
			ev = append(ev, fmt.Sprintf("%.0f%% of their capacity was neither halted nor on a CPU: vCPUs that are offline in the guest, or that idle without a HLT (MWAIT, a polling loop), do not count as halted. Idleness here is a lower bound, so this is not proof the VM is right-sized.", 100*row.UnaccountedFraction))
		}
		row.Advice = append(row.Advice, Advice{Kind: "no_change", Confidence: conf, Summary: "Nothing suggests changing this VM's size.", Evidence: ev})
	}
}
