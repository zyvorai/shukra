package state

import (
	"fmt"
	"sort"

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
)

var confRank = map[string]int{"high": 3, "medium": 2, "low": 1}

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
	block []aggregate.BlockRow, net []aggregate.NetRow) []Finding {
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

	if len(out) == 0 {
		return []Finding{{
			Cause: "no_host_cause", Confidence: "low",
			Summary: "Nothing host-side crossed a threshold. If the guest is slow, the cause may be inside it, which this build does not measure.",
		}}
	}
	sort.SliceStable(out, func(i, j int) bool { return confRank[out[i].Confidence] > confRank[out[j].Confidence] })
	return out
}
