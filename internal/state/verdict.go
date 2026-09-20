package state

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/shukra/internal/aggregate"
)

// Finding is one host-side explanation for a slow VM, ranked by how much the
// evidence supports it. It says where to look, not what is wrong inside the guest.
type Finding struct {
	Cause      string   `json:"cause"`
	Confidence string   `json:"confidence"` // high, medium or low
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Basis is printed with every verdict. The histograms are lifetime, not windowed.
const Basis = "Latencies are since the daemon attached, from log2 buckets, so each can read up to 2x high. " +
	"They are the QEMU process's, not the guest's."

// Thresholds. The 10 and 20 ms lines match the slow-request events in bpf/event.h.
const (
	cpuMediumNs  = 2_000_000
	storageHigh  = 50_000_000
	exitMediumNs = 1_000_000
	exitHighNs   = 10_000_000
	retransFloor = 10
	// A vCPU is preempted when it is runnable and something else has its CPU. Less than this much in the window,
	// or under 5% of the time the vCPUs wanted to run, is ordinary scheduling and not a finding.
	preemptFloorNs = 200_000_000
	preemptMedium  = 0.05
	preemptHigh    = 0.20
	// noisyShare is how much of a VM's preempted time one other VM must account for to be named the cause.
	noisyShare = 0.5
)

var confRank = map[string]int{"high": 3, "medium": 2, "low": 1}

// preemptorName names a preemptor for a person: a thread of another VM, of this VM (its own iothread or another
// vCPU), or a host task.
func preemptorName(label, self string) string {
	name, isVM := strings.CutPrefix(label, aggregate.VMLabel)
	switch {
	case isVM && name == self:
		return "this VM's own other threads"
	case isVM:
		return "VM " + name
	}
	return "host task " + label
}

func dur(ns uint64) string {
	switch {
	case ns >= 1_000_000_000:
		return fmt.Sprintf("%.3g s", float64(ns)/1e9)
	case ns >= 1_000_000:
		return fmt.Sprintf("%.3g ms", float64(ns)/1e6)
	case ns >= 1_000:
		return fmt.Sprintf("%.3g µs", float64(ns)/1e3)
	}
	return fmt.Sprintf("%d ns", ns)
}

// diagnose ranks the host-side causes the counters support. Each input is the
// rows for the one VM being explained.
func diagnose(found bool, kvm []aggregate.KVMRow, sched []aggregate.SchedRow, threads []aggregate.ThreadRow,
	block []aggregate.BlockRow, net []aggregate.NetRow, drops []DropTap, conns *Outcomes) []Finding {
	if !found {
		return []Finding{{Cause: "unknown_vm", Confidence: "high", Summary: "No QEMU process with that name is in the current scan."}}
	}
	measured := (len(kvm) > 0 && kvm[0].Measured) || (len(sched) > 0 && sched[0].Measured) || (len(block) > 0 && block[0].Measured)
	if !measured {
		return []Finding{{
			Cause: "not_measured", Confidence: "high",
			Summary: "No kernel program has measured this VM, so nothing host-side can be said. The programs may be detached: check `shukractl programs`.",
		}}
	}

	var out []Finding

	// Host CPU contention: the vCPU threads waiting for a host CPU after a wakeup.
	var worst uint64
	var who string
	for _, t := range threads {
		if t.Role == "vcpu" && t.WakeupDelayP99Ns > worst {
			worst, who = t.WakeupDelayP99Ns, fmt.Sprintf("vCPU thread %d (%s)", t.TID, t.Comm)
		}
	}
	vcpu := who != ""
	if !vcpu && len(sched) > 0 {
		worst, who = sched[0].WakeupDelayP99Ns, "the VM's threads"
	}
	if worst >= cpuMediumNs {
		conf := "medium"
		if worst >= aggregate.SlowWakeupNS {
			conf = "high"
		}
		if !vcpu {
			conf = "medium" // without a vCPU thread to point at, do not claim more
		}
		out = append(out, Finding{
			Cause: "host_cpu_contention", Confidence: conf,
			Summary:  "The VM's threads wait for a host CPU after being woken. Look at host CPU load, pinning and noisy neighbours.",
			Evidence: []string{fmt.Sprintf("Run-queue delay p99 is up to %s on %s.", dur(worst), who)},
		})
	}

	// vCPU preemption: the host gave the CPU to something else while the vCPU wanted to run. This is what the
	// guest sees as steal, from the host's side, and it says who took the CPU.
	if len(sched) > 0 && sched[0].Measured && sched[0].PreemptedNs >= preemptFloorNs {
		s := sched[0]
		var on uint64
		for _, t := range threads {
			if t.Role == "vcpu" {
				on += t.OnCPUNs
			}
		}
		share := float64(s.PreemptedNs) / float64(on+s.PreemptedNs)
		if share >= preemptMedium {
			conf := "medium"
			if share >= preemptHigh {
				conf = "high"
			}
			ev := []string{fmt.Sprintf("The vCPU threads were runnable but off a host CPU for %s over %d preemptions, %.0f%% of the time they wanted to run.",
				dur(s.PreemptedNs), s.PreemptedCount, share*100)}
			if len(s.Preemptors) > 0 {
				var parts []string
				for _, p := range s.Preemptors {
					parts = append(parts, fmt.Sprintf("%s (%s)", preemptorName(p.Who, s.VM), dur(p.Ns)))
				}
				ev = append(ev, "Taken by: "+strings.Join(parts, ", ")+".")
			}
			out = append(out, Finding{
				Cause: "cpu_preempted", Confidence: conf,
				Summary:  "The host took CPU away from this VM's vCPUs. Look at what else is running on those host CPUs: other VMs, host services, interrupt load, and CPU pinning.",
				Evidence: ev,
			})
			// When most of it went to one other VM, that VM is the finding: it is the thing to move or limit.
			if len(s.Preemptors) > 0 {
				top := s.Preemptors[0]
				if name, isVM := strings.CutPrefix(top.Who, aggregate.VMLabel); isVM && name != s.VM && float64(top.Ns) >= noisyShare*float64(s.PreemptedNs) {
					out = append(out, Finding{
						Cause: "noisy_neighbour", Confidence: conf,
						Summary: fmt.Sprintf("Another VM, %s, took most of the CPU this VM's vCPUs were denied. Look at %s's load, and at CPU pinning or separating the two onto different cores.", name, name),
						Evidence: []string{fmt.Sprintf("%s took %s of the %s the vCPUs were preempted (%.0f%%). shukractl trace contention shows what %s was doing meanwhile.",
							name, dur(top.Ns), dur(s.PreemptedNs), 100*float64(top.Ns)/float64(s.PreemptedNs), name)},
					})
				}
			}
		}
	}

	// Storage: the QEMU I/O thread waiting on the block layer.
	if len(block) > 0 && block[0].Measured {
		b := block[0]
		op, p99, max := "read", b.ReadP99Ns, b.ReadMaxNs
		if b.WriteP99Ns > p99 {
			op, p99, max = "write", b.WriteP99Ns, b.WriteMaxNs
		}
		if p99 >= aggregate.SlowBlockNS {
			conf := "medium"
			if p99 >= storageHigh {
				conf = "high"
			}
			out = append(out, Finding{
				Cause: "storage_latency", Confidence: conf,
				Summary:  "Block requests from QEMU take long. Look at the backing device, its queue depth and other writers.",
				Evidence: []string{fmt.Sprintf("Block %s p99 is up to %s (slowest %s) across %d requests.", op, dur(p99), dur(max), b.ReadOps+b.WriteOps)},
			})
		}
	}

	// KVM exits: the host taking long to service guest exits.
	if len(kvm) > 0 && kvm[0].Measured {
		k := kvm[0]
		if k.LatencyP99Ns >= exitMediumNs {
			conf := "medium"
			if k.LatencyP99Ns >= exitHighNs {
				conf = "high"
			}
			ev := []string{fmt.Sprintf("Exit handling p99 is up to %s (halts excluded).", dur(k.LatencyP99Ns))}
			for _, r := range k.TopByTime {
				if r.Name == "hlt" {
					continue // guest idle, not host work
				}
				name := r.Name
				if name == "" {
					name = fmt.Sprintf("reason %d", r.Reason)
				}
				ev = append(ev, fmt.Sprintf("Costliest exit: %s, %s over %d exits.", name, dur(r.TotalNs), r.Count))
				break
			}
			out = append(out, Finding{
				Cause: "kvm_exit_handling", Confidence: conf,
				Summary:  "The host is slow to service this VM's KVM exits, often device emulation. Look at what the costliest exit reason points to.",
				Evidence: ev,
			})
		}
	}

	if len(net) > 0 && net[0].Retransmits >= retransFloor {
		out = append(out, Finding{
			Cause: "tcp_retransmits", Confidence: "low",
			Summary:  "The QEMU process is retransmitting TCP segments. That is host traffic such as migration or a remote disk, not the guest's own connections.",
			Evidence: []string{fmt.Sprintf("%d retransmits from the QEMU process.", net[0].Retransmits)},
		})
	}

	// Packets the host kernel dropped on the VM's tap. Isolation's own drops are subtracted, so what
	// is left is another program on the tap, or the guest not taking what it is sent.
	for _, d := range drops {
		if d.OtherDrops >= dropFloor {
			ev := fmt.Sprintf("%d packets were dropped on tap %s by something other than Shukra (Shukra dropped %d).", d.OtherDrops, d.Tap, d.ShukraDropped)
			if len(d.Reasons) > 0 {
				ev += " Mostly " + d.Reasons[0].Reason + "."
			}
			out = append(out, Finding{
				Cause: "guest_traffic_dropped", Confidence: "medium",
				Summary:  "The host kernel is dropping this VM's packets, and Shukra's isolation is not the cause. Look for another program attached to the tap (Cilium, a network dataplane, a tc filter): bpftool net show dev " + d.Tap + ".",
				Evidence: []string{ev},
			})
		}
		if d.QueueFull >= dropFloor {
			out = append(out, Finding{
				Cause: "guest_not_reading_nic", Confidence: "medium",
				Summary:  "The tap's queue is full, so the host cannot hand this VM the packets it is sent. The guest is not taking them: it is stalled, has no working NIC driver, or is overloaded.",
				Evidence: []string{fmt.Sprintf("%d packets were dropped on tap %s because its queue was full.", d.QueueFull, d.Tap)},
			})
		}
	}

	// The guest's own connections, seen on its tap: most of them refused or never answered.
	if conns != nil {
		if failing, what := connectFailing(*conns); failing {
			out = append(out, Finding{
				Cause: "guest_connects_failing", Confidence: "medium",
				Summary:  "Most of this VM's outbound TCP connections fail. Refused means nothing is listening on the destination port; never answered means something is dropping the SYN, such as blocked egress or an unreachable network. Many refusals to different ports looks like a scan.",
				Evidence: []string{what + "."},
			})
		}
	}

	if len(out) == 0 {
		return []Finding{{
			Cause: "no_host_cause", Confidence: "low",
			Summary: "Nothing host-side crossed a threshold. If the guest is slow, the cause may be inside it, which this build does not measure.",
		}}
	}
	sort.SliceStable(out, func(i, j int) bool { return confRank[out[i].Confidence] > confRank[out[j].Confidence] })
	return out
}
