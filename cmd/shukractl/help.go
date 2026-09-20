package main

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

type helpCmd struct{ name, desc string }

type helpSection struct {
	title string
	cmds  []helpCmd
}

func helpSections() []helpSection {
	return []helpSection{
		{title: "🖥  Hypervisor", cmds: []helpCmd{
			{"status [--json] [--wait]", "Daemon board: mode, programs, VMs, detections"},
			{"doctor [--json] [--strict]", "Audit the daemon: exposure, what is attached, what it cannot see"},
			{"programs", "Which observation programs are attached"},
			{"install-cli [--prefix DIR]", "Copy this binary onto PATH"},
		}},
		{title: "🔬  Trace", cmds: []helpCmd{
			{"trace list", "kvm, sched, block, net, tap and drops programs"},
			{"trace kvm|sched|block|net|tap|drops [--vm NAME] [--json]", "Per-VM counters from the daemon"},
		}},
		{title: "🔍  Investigate", cmds: []helpCmd{
			{"vms [--json]", "Virtual machines from the host (QEMU and FluxVM)"},
			{"explain <vm> [--window 5m|lifetime]", "Why this VM looks slow, from the last minute by default"},
			{"recorder <vm> [--window 60s]", "Replay the flight recorder"},
			{"watch [--json] [--once]", "Stream discrete events"},
			{"export", "One JSON document: status, VMs, traces, events"},
		}},
		{title: "🛡️  Security", cmds: []helpCmd{
			{"security <vm>", "Watchlist detections for one VM"},
			{"isolate <vm>", "Drop the VM's tap traffic except the management allow list. Says if it was not enforced"},
			{"release <vm>", "Lift an isolation"},
			{"rules check <file> [--json]", "Validate a detection file offline, before reloading"},
		}},
	}
}

func printUsage(w io.Writer) {
	file, _ := w.(*os.File)
	if bannerEnabled() && file != nil && (useColor(file) || isTTY(file)) {
		printBanner(file)
	}
	fmt.Fprintln(w, colorize(file, ansiBold+zyvorOrange, "shukractl")+" — Shukra operator CLI")
	fmt.Fprintln(w, colorize(file, ansiDim, "eBPF-powered runtime intelligence and security for KVM"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(file, ansiBold, "Usage"))
	fmt.Fprintln(w, "  shukractl <command> [flags]")
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, sec := range helpSections() {
		fmt.Fprintln(tw, colorize(file, ansiBold+ansiCyan, sec.title))
		for _, c := range sec.cmds {
			fmt.Fprintf(tw, "%s\t%s\n", colorize(file, ansiGreen, "  "+c.name), colorize(file, ansiDim, c.desc))
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()
	fmt.Fprintln(w, colorize(file, ansiBold, "Environment"))
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, e := range []struct{ k, v string }{
		{"SHUKRA_URL", "daemon URL (default http://127.0.0.1:30970)"},
		{"SHUKRA_API_KEY", "bearer (or ~/.shukra/api-key)"},
		{"SHUKRA_TLS_INSECURE", "skip verify when SHUKRA_URL is https"},
		{"SHUKRA_CLI_COLOR", "true|false (default: color on a TTY)"},
		{"SHUKRA_CLI_NO_BANNER", "set to hide the Zyvor banner"},
		{"NO_COLOR", "disable color (https://no-color.org)"},
	} {
		fmt.Fprintf(tw, "  %s\t%s\n", colorize(file, ansiGreen, e.k), colorize(file, ansiDim, e.v))
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(file, ansiDim, "Docs: docs/shukractl.md  ·  make install  ·  shukractl status"))
}
