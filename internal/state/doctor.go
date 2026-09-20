package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/identity"
)

// Check is one finding of the self-audit. Status is ok, info, warn or fail. Fix
// says what to change, and is empty for an ok.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// ConfigInfo is what the daemon was started with, for the audit. It holds no secret:
// only whether a key is the well-known one, never the key itself.
type ConfigInfo struct {
	Listen       string
	TLS          bool
	NoAuth       bool
	DevKey       bool   // the admin key is the well-known dev token
	KeyLen       int    // length of the admin key, 0 when there is none
	ReadOnlyKey  bool   // a separate read-only key is configured
	DataDir      string // empty means nothing is kept across a restart
	Sinks        []string
	IsolateAllow []string
	RulesFile    string
}

// SetConfig records how the daemon was started, for Doctor.
func (s *State) SetConfig(c ConfigInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = c
}

// SetRulesStatus records whether the detection file loaded, and the error of the
// last attempt if it did not. A failed reload keeps the previous rules, so the
// daemon keeps running on rules the operator may believe were replaced.
func (s *State) SetRulesStatus(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.rulesErr = err.Error()
	} else {
		s.rulesErr = ""
	}
}

var statusRank = map[string]int{"ok": 0, "info": 1, "warn": 2, "fail": 3}

// Doctor audits the running daemon and returns the findings, the worst first.
// It is a read of state, not a probe: it changes nothing and touches no VM.
func (s *State) Doctor() []Check {
	s.mu.RLock()
	c, rulesErr, ready := s.config, s.rulesErr, s.ready
	programs := append([]Program(nil), s.programs...)
	vms := append([]identity.VM(nil), s.vms...)
	enf := s.enforcer
	kernel := s.kernelRelease
	tapSrc := s.tapSource
	exists := s.linkExists
	s.mu.RUnlock()
	if kernel == nil {
		kernel = readKernelRelease
	}
	if exists == nil {
		exists = hostLinkExists
	}
	dropTaps, dropsOver := s.DropTapsOver("", s.now(), DefaultExplainWindow)
	connOutcomes, connOver := s.OutcomesOver("", s.now(), DefaultExplainWindow)

	var out []Check
	add := func(id, status, title, detail, fix string) {
		out = append(out, Check{ID: id, Status: status, Title: title, Detail: detail, Fix: fix})
	}
	public := !isLoopbackAddr(c.Listen)

	// Who can call the API, and what crosses the network.
	switch {
	case c.NoAuth:
		add("auth", "fail", "The API needs no key", "-no-auth is set, so anyone who can reach "+c.Listen+" can read everything and call isolate.",
			"Remove -no-auth and set SHUKRA_API_KEY.")
	case c.DevKey && public:
		add("auth", "fail", "The API key is the well-known dev key, on a non-loopback address",
			"The key \"shukra\" is public knowledge, and the API listens on "+c.Listen+".",
			"Set a real key: SHUKRA_API_KEY=$(openssl rand -hex 16) in /etc/shukra/env, then restart.")
	case c.DevKey:
		add("auth", "warn", "The API key is the well-known dev key", "It is only reachable from this host, but any local user knows it.",
			"Set SHUKRA_API_KEY in /etc/shukra/env.")
	case c.KeyLen > 0 && c.KeyLen < 16:
		add("auth", "warn", "The API key is short", "It is "+strconv.Itoa(c.KeyLen)+" characters.", "Use at least 16: openssl rand -hex 16.")
	default:
		add("auth", "ok", "The API key is not the dev key", "", "")
	}
	switch {
	case c.TLS:
		add("transport", "ok", "The API is served over TLS", "", "")
	case public:
		st := "warn"
		if c.DevKey || c.NoAuth {
			st = "fail"
		}
		add("transport", st, "The API is plain HTTP on a non-loopback address",
			"The bearer key crosses the network in the clear on "+c.Listen+".",
			"Add -tls-cert and -tls-key (SHUKRA_EXTRA_ARGS in /etc/shukra/env), or listen on 127.0.0.1.")
	default:
		add("transport", "ok", "The API is only reachable from this host", "", "")
	}
	if !c.ReadOnlyKey {
		add("readonly-key", "info", "No read-only key", "A scrape or dashboard has to use the admin key, which can also isolate a VM.",
			"Set SHUKRA_READONLY_KEY and give that to Prometheus.")
	}

	// Kernel.
	if rel := kernel(); rel != "" {
		maj, min := parseKernel(rel)
		switch {
		case maj < 5 || (maj == 5 && min < 8):
			add("kernel", "warn", "The kernel is older than 5.8", rel+": no CAP_BPF, so the service runs with full root capabilities.", "Upgrade the kernel if you can.")
		case maj < 6 || (maj == 6 && min < 6):
			add("kernel", "info", "The kernel is older than 6.6", rel+": no TCX, so the tap program cannot attach and guest traffic and isolate are unavailable.", "Upgrade to 6.6 or newer for guest attribution.")
		default:
			add("kernel", "ok", "The kernel supports every program", rel, "")
		}
	}

	// Programs.
	if !ready {
		add("scan", "warn", "The first scan has not finished", "", "")
	}
	tapAttached := false
	detached := map[string][]string{}
	var detachedOrder []string
	for _, p := range programs {
		if p.Name == "tap" && p.Status == "attached" {
			tapAttached = true
		}
		switch {
		case p.Status == "attached" && strings.Contains(p.Detail, "/") && strings.Contains(p.Detail, "hooks"):
			add("program-"+p.Name, "warn", p.Name+" is only partly attached", p.Detail, "Missing hooks are usually a tracepoint this kernel or CPU does not have.")
		case p.Status == "attached":
			// nothing to say
		case p.Name == "tap" && strings.Contains(p.Detail, "no VM tap"):
			add("program-tap", "info", "The tap program has no VM tap to attach to yet", p.Detail, "")
		default:
			detached[p.Detail] = append(detached[p.Detail], p.Name)
			detachedOrder = appendUnique(detachedOrder, p.Detail)
		}
	}
	// Programs detached for the same reason are one finding, not one per program.
	const detachedFix = "Run shukractl programs. On a host built without BPF, rebuild with make generate and -tags shukrabpf."
	for _, reason := range detachedOrder {
		names := detached[reason]
		if len(names) == 1 {
			add("program-"+names[0], "warn", names[0]+" is detached", reason, detachedFix)
			continue
		}
		add("programs-detached", "warn", strconv.Itoa(len(names))+" programs are detached ("+strings.Join(names, ", ")+")", reason, detachedFix)
	}

	// VMs the tap program cannot see.
	var blind []string
	for _, vm := range vms {
		if len(vm.Taps) == 0 {
			blind = append(blind, vm.Name)
		}
	}
	if len(vms) > 0 && len(blind) > 0 {
		st := "info"
		if tapAttached {
			st = "warn"
		}
		add("blind-vms", st, strconv.Itoa(len(blind))+" of "+strconv.Itoa(len(vms))+" VMs have no known tap",
			briefList(blind)+". Their guest traffic is not seen and they cannot be isolated.",
			"A VM on user-mode networking has no tap. For libvirt VMs the daemon needs CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH to read their tap fds: use the shipped unit.")
	}

	// VMs whose tap is named but not traced. Only meaningful once the tap program is
	// attached and there is a source of what it traces.
	if tapSrc != nil && tapAttached {
		traced := map[string]bool{}
		for _, t := range tapSrc() {
			traced[t.Name] = true
		}
		var elsewhere, untraced []string
		elsewhereVMs, untracedVMs := map[string]bool{}, map[string]bool{}
		for _, vm := range vms {
			for _, tap := range vm.Taps {
				switch {
				case traced[tap]:
				case exists(tap):
					untraced = append(untraced, vm.Name+" ("+tap+")")
					untracedVMs[vm.Name] = true
				default:
					elsewhere = append(elsewhere, vm.Name+" ("+tap+")")
					elsewhereVMs[vm.Name] = true
				}
			}
		}
		if len(elsewhere) > 0 {
			add("vm-tap-other-netns", "warn", strconv.Itoa(len(elsewhereVMs))+" of "+strconv.Itoa(len(vms))+" VMs have a tap in another network namespace",
				briefList(elsewhere)+". The interface is not in the namespace this daemon runs in, so its guest traffic is not seen and the VM cannot be isolated.",
				"Shukra attaches in the host network namespace. A FluxVM guest is traced on its host veth, not the tap inside the guest namespace. Any other runtime needs its tap in the host namespace.")
		}
		if len(untraced) > 0 {
			add("vm-tap-untraced", "info", strconv.Itoa(len(untracedVMs))+" VMs have a tap that is not being traced yet",
				briefList(untraced)+". The interface exists here but has no counters: a tap that has just appeared is picked up on the next scan, and one that stays here means the attach failed.",
				"Run shukractl programs and check the daemon log.")
		}
	}

	// What the kernel dropped on the VMs' taps, that Shukra did not: another program on the tap, or a
	// guest not reading its NIC. Nothing is said unless the drops program is measuring.
	var foreign, notReading []string
	for _, d := range dropTaps {
		if d.OtherDrops >= dropFloor {
			why := ""
			if len(d.Reasons) > 0 {
				why = d.Reasons[0].Reason + " "
			}
			foreign = append(foreign, fmt.Sprintf("%s (%s: %s%d)", d.VM, d.Tap, why, d.OtherDrops))
		}
		if d.QueueFull >= dropFloor {
			notReading = append(notReading, fmt.Sprintf("%s (%s: %d)", d.VM, d.Tap, d.QueueFull))
		}
	}
	if len(foreign) > 0 {
		add("vm-drops-not-shukra", "warn", strconv.Itoa(len(foreign))+" VMs have traffic dropped on their tap by something other than Shukra",
			briefList(foreign)+" over "+dropsOver+". Shukra's own isolation drops are already subtracted.",
			"Something else attached to the tap is dropping it: Cilium, a network dataplane, a tc filter. Run bpftool net show dev <tap>, and see docs/tap.md, \"When guests cannot reach each other\".")
	}
	if len(notReading) > 0 {
		add("vm-nic-not-consumed", "warn", strconv.Itoa(len(notReading))+" VMs are not reading their NIC",
			briefList(notReading)+" packets were dropped over "+dropsOver+" because the tap's queue was full.",
			"The guest is stalled, has no working network driver, or is overloaded. Look at the VM itself.")
	}

	// VMs whose own outbound connections mostly fail, as seen on their taps.
	var failing []string
	for _, vm := range vms {
		if ok, what := connectFailing(connOutcomes[vm.Name]); ok {
			failing = append(failing, vm.Name+" ("+what+")")
		}
	}
	if len(failing) > 0 {
		add("vm-connects-failing", "warn", strconv.Itoa(len(failing))+" VMs have outbound connections that mostly fail",
			briefList(failing)+" over "+connOver+".",
			"Refused: nothing listens on that port. Never answered: something drops the SYN, such as blocked egress or an unreachable network. Many refusals to different ports looks like a scan. shukractl trace tap --vm <vm> has the counts.")
	}

	// Isolation.
	switch {
	case enf == nil:
		add("isolate", "info", "Isolate is not available in this build", "", "")
	default:
		if ok, why := enf.Available(); !ok {
			st := "info"
			fix := "Start the daemon with -isolate-allow <management CIDRs> to enable it."
			if len(c.IsolateAllow) > 0 {
				st, fix = "warn", "Check shukractl programs: the tap program has to be attached."
			}
			add("isolate", st, "Isolate is not enabled", why, fix)
		} else if !enf.Durable() {
			add("isolate", "warn", "Isolation will not survive the daemon", "There is no bpf filesystem to pin on, so a restart reopens an isolated VM until it re-applies.", "Mount bpffs at /sys/fs/bpf.")
		} else {
			add("isolate", "ok", "Isolate is enabled and survives the daemon", "Management allow list: "+strings.Join(enf.AllowList(), ", "), "")
		}
	}

	// What is kept and where alerts go.
	if c.DataDir == "" {
		add("persistence", "warn", "Nothing is kept across a restart", "Detections, isolation records and the flight recorder are lost, and recorded isolations cannot be re-applied.",
			"Start with -data-dir /var/lib/shukra (the shipped unit does).")
	} else {
		add("persistence", "ok", "State is kept in "+c.DataDir, "", "")
	}
	if len(c.Sinks) == 0 {
		add("alerts", "info", "No alert sink is configured", "Detections are only visible in the console, the CLI and /metrics.", "Add -webhook-url, -syslog or -alert-file.")
	} else {
		add("alerts", "ok", "Detections are delivered to "+strings.Join(c.Sinks, ", "), "", "")
	}
	switch {
	case rulesErr != "":
		add("rules", "fail", "The detection file did not reload", rulesErr+". The previous rules are still in force.", "Fix the file, check it with shukractl rules check "+c.RulesFile+", then systemctl reload shukra.")
	case c.RulesFile == "":
		add("rules", "info", "No detection file is configured", "Only the built-in unexpected-exec check runs.", "Start with -watchlist /etc/shukra/detections.yaml.")
	default:
		add("rules", "ok", "Detection rules loaded from "+c.RulesFile, "", "")
	}

	// Learned baselines, only when the rules file has turned them on.
	if bv := s.Baselines(); bv != nil && bv.Enabled() {
		rows := bv.Status("", s.now())
		learning := 0
		var until time.Time
		for _, r := range rows {
			if r.Learning {
				learning++
				if until.IsZero() || r.LearnUntil.After(until) {
					until = r.LearnUntil
				}
			}
		}
		switch {
		case !bv.Persisted():
			add("baselines", "warn", "Learned baselines are on but nothing is kept across a restart",
				"Learning starts over each time the daemon does, so a daemon that restarts more often than the learning period ("+bv.Options().Learn.String()+") never reports anything.",
				"Start with -data-dir /var/lib/shukra (the shipped unit does).")
		case learning > 0:
			add("baselines", "info", strconv.Itoa(learning)+" of "+strconv.Itoa(len(rows))+" VMs are still learning their baseline",
				"Nothing is reported for a VM until its learning period ends; the last ends "+until.UTC().Format(time.RFC3339)+".", "")
		default:
			add("baselines", "ok", "Learned baselines are reporting what is new for "+strconv.Itoa(len(rows))+" VMs", "", "")
		}
	}

	// Responses, only when the rules file has them.
	if av := s.Actions(); av != nil && av.Enabled() {
		propose, enforce, dry := av.Modes()
		desc := strconv.Itoa(propose) + " propose, " + strconv.Itoa(enforce) + " enforce, " + strconv.Itoa(dry) + " dry run"
		pending := av.Counts()["pending"]
		mode, _, why := s.Enforcement()
		switch {
		case mode != "tcx" && propose+enforce > 0:
			add("responses", "warn", "Responses are configured but isolate is not enabled, so every action will be refused",
				desc+". "+why, "Start the daemon with -isolate-allow <management CIDRs>, or make the responses dry runs.")
		case pending > 0:
			add("responses", "warn", strconv.Itoa(pending)+" proposed isolations are waiting for a decision",
				desc+". A proposal lapses if nobody decides.", "shukractl actions, then shukractl approve <id> or reject <id>.")
		default:
			add("responses", "ok", "Responses are configured ("+desc+")", "", "")
		}
	}

	// Worst first, and stable within a status.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && statusRank[out[j].Status] > statusRank[out[j-1].Status]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func isLoopbackAddr(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "127.")
}

func parseKernel(rel string) (major, minor int) {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) >= 2 {
		major, _ = strconv.Atoi(parts[0])
		minor, _ = strconv.Atoi(strings.TrimFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	}
	return
}

func readKernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// briefList names the first five and counts the rest.
func briefList(names []string) string {
	if len(names) <= 5 {
		return strings.Join(names, ", ")
	}
	return strings.Join(append(append([]string(nil), names[:5]...), fmt.Sprintf("and %d more", len(names)-5)), ", ")
}

// hostLinkExists reports whether an interface is in this network namespace.
func hostLinkExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}
