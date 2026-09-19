package api

import (
	"fmt"
	"io"
	"strings"

	"github.com/zyvorai/shukra/internal/state"
)

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// writeMetrics renders Prometheus text format. A row that is not measured is
// skipped, so an absent series means "not measured", not zero. VM names come from
// the QEMU command line and are escaped.
func writeMetrics(w io.Writer, st *state.State) {
	s := st.Status()
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
	kvm := st.KVM("")
	for _, r := range kvm {
		if r.Measured {
			fmt.Fprintf(w, "shukra_kvm_exits_total{%s} %d\n", lbl(r.VM), r.Exits)
		}
	}
	counter("shukra_sched_on_cpu_seconds_total", "On-CPU time of the QEMU thread group.")
	sched := st.Sched("")
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
	gauge("shukra_block_latency_seconds", "Block request latency on the QEMU iothread, not the guest filesystem.")
	for _, r := range st.Block("") {
		if !r.Measured {
			continue
		}
		fmt.Fprintf(w, "shukra_block_latency_seconds{%s,op=\"read\",quantile=\"0.5\"} %g\n", lbl(r.VM), float64(r.ReadP50Ns)/1e9)
		fmt.Fprintf(w, "shukra_block_latency_seconds{%s,op=\"read\",quantile=\"0.99\"} %g\n", lbl(r.VM), float64(r.ReadP99Ns)/1e9)
		fmt.Fprintf(w, "shukra_block_latency_seconds{%s,op=\"write\",quantile=\"0.5\"} %g\n", lbl(r.VM), float64(r.WriteP50Ns)/1e9)
		fmt.Fprintf(w, "shukra_block_latency_seconds{%s,op=\"write\",quantile=\"0.99\"} %g\n", lbl(r.VM), float64(r.WriteP99Ns)/1e9)
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
