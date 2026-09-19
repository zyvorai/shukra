package api

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/state"
)

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// writeMetrics renders Prometheus text format. A row that is not measured is
// skipped, so an absent series means "not measured", not zero. VM names come from
// the QEMU command line and are escaped.
func writeMetrics(w io.Writer, st *state.State) {
	s := st.Status()
	kvm := st.KVM("")
	sched := st.Sched("")
	gauge := func(name, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	counter := func(name, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	}
	lbl := func(vm string) string { return `vm="` + labelEscaper.Replace(vm) + `"` }

	gauge("shukra_vms", "QEMU VMs found in the last /proc scan.")
	fmt.Fprintf(w, "shukra_vms %d\n", s.VMs)
	gauge("shukra_program_attached", "1 when the eBPF program is attached.")
	for _, p := range st.Programs() {
		v := 0
		if p.Status == "attached" {
			v = 1
		}
		fmt.Fprintf(w, "shukra_program_attached{program=%q} %d\n", p.Name, v)
	}
	counter("shukra_events_total", "Discrete events stored since the daemon started.")
	fmt.Fprintf(w, "shukra_events_total %d\n", st.Seq())
	gauge("shukra_detections", "Detections currently held in memory.")
	fmt.Fprintf(w, "shukra_detections %d\n", s.Detections)

	counter("shukra_detections_suppressed_total", "Detections held back as repeats of one already raised.")
	fmt.Fprintf(w, "shukra_detections_suppressed_total %d\n", st.Suppressed())
	if sinks := st.SinkStats(); len(sinks) > 0 {
		counter("shukra_alert_sent_total", "Detections delivered to an alert sink.")
		for _, k := range sinks {
			fmt.Fprintf(w, "shukra_alert_sent_total{sink=%q} %d\n", k.Name, k.Sent)
		}
		counter("shukra_alert_failed_total", "Detections an alert sink failed to deliver after retries.")
		for _, k := range sinks {
			fmt.Fprintf(w, "shukra_alert_failed_total{sink=%q} %d\n", k.Name, k.Failed)
		}
		counter("shukra_alert_dropped_total", "Detections dropped because a sink's queue was full.")
		for _, k := range sinks {
			fmt.Fprintf(w, "shukra_alert_dropped_total{sink=%q} %d\n", k.Name, k.Dropped)
		}
	}

	counter("shukra_kvm_exits_total", "KVM exits for the QEMU thread group.")
	for _, r := range kvm {
		if r.Measured {
			fmt.Fprintf(w, "shukra_kvm_exits_total{%s} %d\n", lbl(r.VM), r.Exits)
		}
	}
	counter("shukra_sched_on_cpu_seconds_total", "On-CPU time of the QEMU thread group.")
	for _, r := range sched {
		if r.Measured {
			fmt.Fprintf(w, "shukra_sched_on_cpu_seconds_total{%s} %g\n", lbl(r.VM), float64(r.OnCPUNs)/1e9)
		}
	}
	counter("shukra_sched_wakeup_delay_seconds_total", "Summed wakeup delay of the QEMU thread group.")
	for _, r := range sched {
		if r.Measured {
			fmt.Fprintf(w, "shukra_sched_wakeup_delay_seconds_total{%s} %g\n", lbl(r.VM), float64(r.WakeupDelayNs)/1e9)
		}
	}
	counter("shukra_sched_vcpu_preempted_seconds_total", "Time the VM's vCPU threads were runnable but off a host CPU after being preempted. The host's view of losing the CPU, not the guest's steal counter.")
	for _, r := range sched {
		if r.Measured && r.VM != aggregate.Host { // the rest of the host has no vCPUs
			fmt.Fprintf(w, "shukra_sched_vcpu_preempted_seconds_total{%s} %g\n", lbl(r.VM), float64(r.PreemptedNs)/1e9)
		}
	}
	counter("shukra_sched_vcpu_preempted_by_seconds_total", "The same, by who took the CPU: by=\"vm:<name>\" for a thread of a QEMU process, otherwise a command name.")
	for _, r := range sched {
		if !r.Measured || r.VM == aggregate.Host {
			continue
		}
		who := append([]aggregate.Preemptor(nil), r.AllPreemptors...)
		sort.Slice(who, func(i, j int) bool { return who[i].Who < who[j].Who })
		for _, p := range who {
			fmt.Fprintf(w, "shukra_sched_vcpu_preempted_by_seconds_total{%s,by=\"%s\"} %g\n", lbl(r.VM), labelEscaper.Replace(p.Who), float64(p.Ns)/1e9)
		}
	}
	block := st.Block("")
	var readH, writeH []histSeries
	counter("shukra_block_ops_total", "Completed block requests by the QEMU iothread, not the guest filesystem.")
	for _, r := range block {
		if r.Measured {
			fmt.Fprintf(w, "shukra_block_ops_total{%s,op=\"read\"} %d\nshukra_block_ops_total{%s,op=\"write\"} %d\n", lbl(r.VM), r.ReadOps, lbl(r.VM), r.WriteOps)
			readH = append(readH, histSeries{lbl(r.VM) + `,op="read"`, r.ReadHist})
			writeH = append(writeH, histSeries{lbl(r.VM) + `,op="write"`, r.WriteHist})
		}
	}
	counter("shukra_block_bytes_total", "Bytes completed by the QEMU iothread, not the guest filesystem.")
	for _, r := range block {
		if r.Measured {
			fmt.Fprintf(w, "shukra_block_bytes_total{%s,op=\"read\"} %d\nshukra_block_bytes_total{%s,op=\"write\"} %d\n", lbl(r.VM), r.ReadBytes, lbl(r.VM), r.WriteBytes)
		}
	}
	gauge("shukra_block_latency_max_seconds", "Slowest block request since the daemon attached. Racy across CPUs; it can miss a slightly smaller maximum.")
	for _, r := range block {
		if r.Measured {
			fmt.Fprintf(w, "shukra_block_latency_max_seconds{%s,op=\"read\"} %g\nshukra_block_latency_max_seconds{%s,op=\"write\"} %g\n",
				lbl(r.VM), float64(r.ReadMaxNs)/1e9, lbl(r.VM), float64(r.WriteMaxNs)/1e9)
		}
	}
	writeHistograms(w, "shukra_block_latency_seconds", "Block request latency on the QEMU iothread, not the guest filesystem.", append(readH, writeH...))

	var rq []histSeries
	for _, r := range sched {
		if r.Measured && len(r.WakeupHist) > 0 {
			rq = append(rq, histSeries{lbl(r.VM), r.WakeupHist})
		}
	}
	writeHistograms(w, "shukra_sched_runqueue_delay_seconds", "Delay from wakeup to running for the QEMU threads.", rq)

	var kl []histSeries
	counter("shukra_kvm_exits_by_reason_total", "KVM exits by reason. name is set only where the numbering is known for this CPU.")
	for _, r := range kvm {
		if !r.Measured {
			continue
		}
		if len(r.LatencyHist) > 0 {
			kl = append(kl, histSeries{lbl(r.VM), r.LatencyHist})
		}
		for _, re := range r.AllReasons {
			fmt.Fprintf(w, "shukra_kvm_exits_by_reason_total{%s} %d\n", reasonLabels(r.VM, re), re.Count)
		}
	}
	counter("shukra_kvm_exit_handling_seconds_total", "Host time spent handling KVM exits by reason. For a halt this is guest idle time.")
	for _, r := range kvm {
		if !r.Measured {
			continue
		}
		for _, re := range r.AllReasons {
			if re.TotalNs > 0 {
				fmt.Fprintf(w, "shukra_kvm_exit_handling_seconds_total{%s} %g\n", reasonLabels(r.VM, re), float64(re.TotalNs)/1e9)
			}
		}
	}
	writeHistograms(w, "shukra_kvm_exit_latency_seconds", "KVM exit handling time, kvm_exit to the next kvm_entry. Halts are excluded.", kl)

	taps := st.Taps("")
	if len(taps) > 0 {
		counter("shukra_tap_bytes_total", "Bytes on a VM tap, from the guest's point of view. This is the guest's own traffic.")
		for _, t := range taps {
			fmt.Fprintf(w, "shukra_tap_bytes_total{%s,tap=%q,direction=\"from_guest\"} %d\nshukra_tap_bytes_total{%s,tap=%q,direction=\"to_guest\"} %d\n",
				lbl(t.VM), t.Tap, t.FromBytes, lbl(t.VM), t.Tap, t.ToBytes)
		}
		counter("shukra_tap_packets_total", "Packets on a VM tap, from the guest's point of view.")
		for _, t := range taps {
			fmt.Fprintf(w, "shukra_tap_packets_total{%s,tap=%q,direction=\"from_guest\"} %d\nshukra_tap_packets_total{%s,tap=%q,direction=\"to_guest\"} %d\n",
				lbl(t.VM), t.Tap, t.FromPkts, lbl(t.VM), t.Tap, t.ToPkts)
		}
		counter("shukra_tap_dropped_packets_total", "Packets isolation dropped on a VM tap.")
		for _, t := range taps {
			fmt.Fprintf(w, "shukra_tap_dropped_packets_total{%s,tap=%q} %d\n", lbl(t.VM), t.Tap, t.DroppedPkts)
		}
		// What became of the TCP handshakes. direction=out is the guest's own connections, in is made to it.
		counter("shukra_tap_connect_attempts_total", "New TCP connection attempts seen on a VM tap. A repeat of the same SYN is a retransmit, not a new attempt.")
		for _, t := range taps {
			fmt.Fprintf(w, "shukra_tap_connect_attempts_total{%s,tap=%q,direction=\"out\"} %d\nshukra_tap_connect_attempts_total{%s,tap=%q,direction=\"in\"} %d\n",
				lbl(t.VM), t.Tap, t.OutSyn, lbl(t.VM), t.Tap, t.InSyn)
		}
		counter("shukra_tap_connect_outcomes_total", "What became of them: accepted (SYN-ACK), refused (RST), timed_out or ignored (never answered), or blocked (dropped by isolation).")
		for _, t := range taps {
			for _, o := range []struct {
				dir, result string
				n           uint64
			}{
				{"out", "accepted", t.OutOK}, {"out", "refused", t.OutRefused}, {"out", "timed_out", t.OutTimeout}, {"out", "blocked", t.OutBlocked},
				{"in", "accepted", t.InOK}, {"in", "refused", t.InRefused}, {"in", "ignored", t.InIgnored}, {"in", "blocked", t.InBlocked},
			} {
				fmt.Fprintf(w, "shukra_tap_connect_outcomes_total{%s,tap=%q,direction=%q,result=%q} %d\n", lbl(t.VM), t.Tap, o.dir, o.result, o.n)
			}
		}
		counter("shukra_tap_connect_retransmits_total", "SYNs repeated on a connection that had not been answered yet.")
		for _, t := range taps {
			fmt.Fprintf(w, "shukra_tap_connect_retransmits_total{%s,tap=%q,direction=\"out\"} %d\nshukra_tap_connect_retransmits_total{%s,tap=%q,direction=\"in\"} %d\n",
				lbl(t.VM), t.Tap, t.OutRetrans, lbl(t.VM), t.Tap, t.InRetrans)
		}
		var hs []histSeries
		for _, t := range taps {
			if len(t.HandshakeHist) > 0 {
				hs = append(hs, histSeries{lbl(t.VM) + fmt.Sprintf(",tap=%q", t.Tap), t.HandshakeHist})
			}
		}
		writeHistograms(w, "shukra_tap_handshake_seconds", "How long the guest's outbound TCP connections took to be answered, SYN to SYN-ACK, seen on the tap.", hs)
		gauge("shukra_tap_isolated", "1 while the VM tap is isolated.")
		for _, t := range taps {
			v := 0
			if t.Isolated {
				v = 1
			}
			fmt.Fprintf(w, "shukra_tap_isolated{%s,tap=%q} %d\n", lbl(t.VM), t.Tap, v)
		}
	}
	// Only while the drops program is measuring: a VM it cannot see has no series, never a zero. The
	// per-reason counts only grow, so this is a counter. What is Shukra's and what is not is a difference
	// of two counters read a moment apart, which can dip, so it is served on the API and not here.
	if drops, _ := st.Drops(""); len(drops) > 0 {
		counter("shukra_tap_kernel_drops_total", "Packets the kernel dropped on a VM tap, by the kernel's own reason. Shukra's isolation drops appear here as TC_INGRESS or TC_EGRESS.")
		for _, d := range drops {
			fmt.Fprintf(w, "shukra_tap_kernel_drops_total{%s,tap=%q,reason=%q} %d\n", lbl(d.VM), d.Tap, d.Reason, d.Count)
		}
	}
	net := st.Net("")
	counter("shukra_tcp_connects_total", "tcp_v4_connect from the QEMU process. Not guest traffic.")
	for _, r := range net {
		fmt.Fprintf(w, "shukra_tcp_connects_total{%s} %d\n", lbl(r.VM), r.Connects)
	}
	counter("shukra_tcp_retransmits_total", "tcp_retransmit_skb from the QEMU process. Not guest traffic.")
	for _, r := range net {
		fmt.Fprintf(w, "shukra_tcp_retransmits_total{%s} %d\n", lbl(r.VM), r.Retransmits)
	}
}

func reasonLabels(vm string, r aggregate.Reason) string {
	l := `vm="` + labelEscaper.Replace(vm) + `",reason="` + strconv.FormatUint(uint64(r.Reason), 10) + `"`
	if r.Name != "" {
		l += `,name="` + r.Name + `"`
	}
	return l
}

type histSeries struct {
	labels string
	counts []uint64 // log2 ns buckets, as in internal/hist
}

// The kernel histograms are log2 buckets, bucket i covering up to 2^(i+1) ns.
// Everything below firstLE is folded into the first bucket. The set of le values
// is fixed so a series keeps the same buckets from scrape to scrape.
const (
	firstLE = 6  // le = 2^7 ns
	lastLE  = 36 // le = 2^37 ns, about 137 s. Anything slower is only in +Inf
)

// writeHistograms renders cumulative Prometheus histograms so histogram_quantile
// over rate() gives windowed percentiles. There is no _sum: the kernel keeps
// buckets, not a total, and one made up from bucket midpoints would be invented.
func writeHistograms(w io.Writer, name, help string, series []histSeries) {
	if len(series) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for _, s := range series {
		var total uint64
		for _, c := range s.counts {
			total += c
		}
		var cum uint64
		for i := 0; i <= lastLE && i < len(s.counts); i++ {
			cum += s.counts[i]
			if i >= firstLE {
				le := float64(uint64(1)<<(i+1)) / 1e9
				fmt.Fprintf(w, "%s_bucket{%s,le=\"%s\"} %d\n", name, s.labels, strconv.FormatFloat(le, 'g', -1, 64), cum)
			}
		}
		fmt.Fprintf(w, "%s_bucket{%s,le=\"+Inf\"} %d\n%s_count{%s} %d\n", name, s.labels, total, name, s.labels, total)
	}
}
