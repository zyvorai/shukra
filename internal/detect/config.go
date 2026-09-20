package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
	"gopkg.in/yaml.v3"
)

// Metrics a threshold rule can watch. Each is computed per VM over the rule's
// window from the cumulative counters, so it needs the kernel programs attached.
const (
	MetricBlockReadP99MS    = "block_read_p99_ms"
	MetricBlockWriteP99MS   = "block_write_p99_ms"
	MetricWakeupDelayMS     = "wakeup_delay_ms"
	MetricKVMExitsPerSec    = "kvm_exits_per_sec"
	MetricRetransmitsPerSec = "tcp_retransmits_per_sec"
	MetricKVMExitP99MS      = "kvm_exit_latency_p99_ms"
	MetricRunqueueP99MS     = "runqueue_delay_p99_ms"
	MetricBlockReadBPS      = "block_read_bytes_per_sec"
	MetricBlockWriteBPS     = "block_write_bytes_per_sec"
	MetricBlockIOPS         = "block_iops"
	// MetricVCPUPreemptedMSPerSec is how many milliseconds per second the VM's vCPU threads were runnable but
	// off a host CPU, summed over its vCPUs (so a 4-vCPU VM can exceed 1000). It is the host's view of losing
	// the CPU, not the guest's steal counter, and needs the sched program.
	MetricVCPUPreemptedMSPerSec = "vcpu_preempted_ms_per_sec"
	// MetricGuestDropsPerSec counts packets the kernel dropped on a VM's tap that Shukra did not: another
	// program on the tap, not isolation. It needs the drops program, and says nothing without it.
	MetricGuestDropsPerSec = "guest_drops_per_sec"
	// The guest's TCP connections, from the handshakes seen on its tap. Refused is an RST, a timeout is a SYN
	// nobody answered (blocked egress, a black hole), and inbound is connections attempted to the guest.
	MetricConnectRefusedPerSec  = "guest_connect_refused_per_sec"
	MetricConnectTimeoutsPerSec = "guest_connect_timeouts_per_sec"
	MetricInboundPerSec         = "guest_inbound_per_sec"
)

var metrics = map[string]bool{
	MetricBlockReadP99MS: true, MetricBlockWriteP99MS: true, MetricWakeupDelayMS: true,
	MetricKVMExitsPerSec: true, MetricRetransmitsPerSec: true,
	MetricKVMExitP99MS: true, MetricRunqueueP99MS: true, MetricVCPUPreemptedMSPerSec: true,
	MetricBlockReadBPS: true, MetricBlockWriteBPS: true, MetricBlockIOPS: true,
	MetricGuestDropsPerSec: true, MetricConnectRefusedPerSec: true, MetricConnectTimeoutsPerSec: true, MetricInboundPerSec: true,
}

var severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

const (
	// DefaultSuppress is how long a repeat of the same detection is held back.
	DefaultSuppress = 5 * time.Minute
	// DefaultWindow is a threshold's window when the rule does not set one.
	DefaultWindow = 30 * time.Second
	minWindow     = 5 * time.Second
	// maxWindow bounds the counter history kept per VM for windowed rules.
	maxWindow = 10 * time.Minute
)

// PortRule notices a connect to a destination port, whatever the address.
type PortRule struct {
	Port uint16 `yaml:"port"`
	// Proto is "tcp" (the default, so an existing rule means what it always did),
	// "udp", or "any".
	Proto string `yaml:"proto"`
	// Dir is "out" (the default, so an existing rule means what it always did: a connect the VM made),
	// "in" (a connect made TO the VM, matched on the port it connected to), or "any".
	Dir      string `yaml:"dir"`
	Severity string `yaml:"severity"`
	Name     string `yaml:"name"`
}

// DNSRule notices a name the guest looked up. Exactly one of Suffix, Exact or Contains is set. Names are
// compared in lower case, so a rule does not depend on how the guest wrote it.
type DNSRule struct {
	Name string `yaml:"name"`
	// Suffix matches the name itself and everything under it: "example.com" matches example.com and
	// a.b.example.com, but not badexample.com.
	Suffix   string `yaml:"suffix"`
	Exact    string `yaml:"exact"`
	Contains string `yaml:"contains"`
	Severity string `yaml:"severity"`
}

func (r DNSRule) matches(name string) bool {
	switch {
	case r.Exact != "":
		return name == r.Exact
	case r.Suffix != "":
		return name == r.Suffix || strings.HasSuffix(name, "."+r.Suffix)
	case r.Contains != "":
		return strings.Contains(name, r.Contains)
	}
	return false
}

// BaselineConfig turns on learned baselines: what is new for a VM, without a rule for it. It is off unless the
// rules file has a baselines section, because it raises detections of its own.
type BaselineConfig struct {
	// Learn is how long each VM is only observed, from the first time it is seen (default 24h).
	Learn time.Duration `yaml:"learn"`
	// MaxAlertsPerDay bounds the new-item alerts one VM raises in a day (default 20).
	MaxAlertsPerDay int `yaml:"max_alerts_per_day"`
	// MaxItems bounds each kind's set per VM (default 2048).
	MaxItems int `yaml:"max_items"`
	// MaxAge is how long an unseen item is remembered (default 720h).
	MaxAge time.Duration `yaml:"max_age"`
	// Kinds limits which of destination, dns-suffix and inbound-peer are learned (default all three).
	Kinds []string `yaml:"kinds"`
	// Severity sets a kind's severity (defaults: destination medium, dns-suffix low, inbound-peer medium).
	Severity map[string]string `yaml:"severity"`
}

// Options is what the baseline store runs with.
func (b *BaselineConfig) Options() baseline.Options {
	return baseline.Options{Learn: b.Learn, MaxItems: b.MaxItems, MaxAge: b.MaxAge, MaxAlertsPerDay: b.MaxAlertsPerDay}
}

// Learns says whether a kind is learned.
func (b *BaselineConfig) Learns(k baseline.Kind) bool {
	if b == nil {
		return false
	}
	for _, x := range b.Kinds {
		if x == string(k) {
			return true
		}
	}
	return false
}

// SeverityOf is the severity a new item of a kind is reported with.
func (b *BaselineConfig) SeverityOf(k baseline.Kind) string {
	if s := b.Severity[string(k)]; s != "" {
		return s
	}
	if k == baseline.DNSSuffix {
		return "low"
	}
	return "medium"
}

func (b *BaselineConfig) validate() error {
	d := baseline.DefaultOptions()
	if b.Learn == 0 {
		b.Learn = d.Learn
	}
	if b.Learn < time.Minute || b.Learn > 90*24*time.Hour {
		return fmt.Errorf("baselines: learn %s is outside 1m to %s", b.Learn, 90*24*time.Hour)
	}
	if b.MaxAlertsPerDay == 0 {
		b.MaxAlertsPerDay = d.MaxAlertsPerDay
	}
	if b.MaxAlertsPerDay < 1 || b.MaxAlertsPerDay > 1000 {
		return fmt.Errorf("baselines: max_alerts_per_day %d is outside 1 to 1000", b.MaxAlertsPerDay)
	}
	if b.MaxItems == 0 {
		b.MaxItems = d.MaxItems
	}
	if b.MaxItems < 16 || b.MaxItems > 100000 {
		return fmt.Errorf("baselines: max_items %d is outside 16 to 100000", b.MaxItems)
	}
	if b.MaxAge == 0 {
		b.MaxAge = d.MaxAge
	}
	if b.MaxAge < b.Learn {
		return fmt.Errorf("baselines: max_age %s is shorter than learn %s, so everything would be forgotten before learning ends", b.MaxAge, b.Learn)
	}
	valid := map[string]bool{}
	for _, k := range baseline.Kinds {
		valid[string(k)] = true
	}
	if len(b.Kinds) == 0 {
		for _, k := range baseline.Kinds {
			b.Kinds = append(b.Kinds, string(k))
		}
	}
	seen := map[string]bool{}
	for _, k := range b.Kinds {
		if !valid[k] {
			return fmt.Errorf("baselines: kind %q is not destination, dns-suffix or inbound-peer", k)
		}
		if seen[k] {
			return fmt.Errorf("baselines: kind %q is listed twice", k)
		}
		seen[k] = true
	}
	for k, sev := range b.Severity {
		if !valid[k] {
			return fmt.Errorf("baselines: severity for %q: not destination, dns-suffix or inbound-peer", k)
		}
		if !severities[sev] {
			return fmt.Errorf("baselines: severity %q for %s is not low, medium, high or critical", sev, k)
		}
	}
	return nil
}

// Threshold notices a per-VM metric over a window. Op is ">" or ">=".
type Threshold struct {
	Name     string        `yaml:"name"`
	Metric   string        `yaml:"metric"`
	Op       string        `yaml:"op"`
	Value    float64       `yaml:"value"`
	Window   time.Duration `yaml:"window"`
	Severity string        `yaml:"severity"`
}

// Config is everything the detection file can say.
type Config struct {
	// Watch is the destination watchlist. It is never nil.
	Watch *Watchlist
	Ports []PortRule
	DNS   []DNSRule
	// Baselines is nil unless the rules file turns learned baselines on.
	Baselines  *BaselineConfig
	ExecAllow  []string
	Thresholds []Threshold
	// Suppress is how long a repeat of the same detection is held back.
	// Zero turns suppression off.
	Suppress time.Duration
}

// DefaultConfig is what runs when no detection file is given: no rules, and the
// built-in unexpected-exec check with default suppression.
func DefaultConfig() *Config {
	return &Config{Watch: &Watchlist{}, Suppress: DefaultSuppress}
}

type doc struct {
	Suppress     *time.Duration  `yaml:"suppress"`
	Destinations []Rule          `yaml:"destinations"`
	Ports        []PortRule      `yaml:"ports"`
	DNS          []DNSRule       `yaml:"dns"`
	Baselines    *BaselineConfig `yaml:"baselines"`
	ExecAllow    []string        `yaml:"exec_allow"`
	Thresholds   []Threshold     `yaml:"thresholds"`
}

// Parse loads and validates a detection file. It is strict: an unknown key is an
// error, because a misspelled section would otherwise turn a rule off without a
// word. An empty document is the default config.
func Parse(b []byte) (*Config, error) {
	var d doc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New(strings.ReplaceAll(err.Error(), "detect.doc", "the detection file"))
	}
	c := DefaultConfig()
	if d.Suppress != nil {
		if *d.Suppress < 0 {
			return nil, fmt.Errorf("suppress %s is negative", *d.Suppress)
		}
		c.Suppress = *d.Suppress
	}
	for _, r := range d.Destinations {
		if r.Severity != "" && !severities[r.Severity] {
			return nil, fmt.Errorf("destination %q: severity %q is not low, medium, high or critical", r.Name, r.Severity)
		}
	}
	w, err := compile(d.Destinations)
	if err != nil {
		return nil, err
	}
	c.Watch = w

	seen := map[string]bool{}
	name := func(kind, n string) error {
		if seen[n] {
			return fmt.Errorf("%s: name %q is used twice", kind, n)
		}
		seen[n] = true
		return nil
	}
	for _, r := range d.Ports {
		if r.Port == 0 {
			return nil, fmt.Errorf("ports: rule %q needs a port from 1 to 65535", r.Name)
		}
		if r.Name == "" {
			r.Name = fmt.Sprintf("port-%d", r.Port)
		}
		switch r.Proto {
		case "":
			r.Proto = "tcp"
		case "tcp", "udp", "any":
		default:
			return nil, fmt.Errorf("ports: %q: proto %q is not tcp, udp or any", r.Name, r.Proto)
		}
		switch r.Dir {
		case "":
			r.Dir = "out"
		case "out", "in", "any":
		default:
			return nil, fmt.Errorf("ports: %q: dir %q is not out, in or any", r.Name, r.Dir)
		}
		if r.Severity == "" {
			r.Severity = "high"
		}
		if !severities[r.Severity] {
			return nil, fmt.Errorf("ports: %q: severity %q is not low, medium, high or critical", r.Name, r.Severity)
		}
		if err := name("ports", r.Name); err != nil {
			return nil, err
		}
		c.Ports = append(c.Ports, r)
	}
	for _, r := range d.DNS {
		set := 0
		norm := func(v string) string { return strings.Trim(strings.ToLower(strings.TrimSpace(v)), ".") }
		r.Suffix, r.Exact = norm(r.Suffix), norm(r.Exact)
		r.Contains = strings.ToLower(strings.TrimSpace(r.Contains))
		for _, v := range []string{r.Suffix, r.Exact, r.Contains} {
			if v != "" {
				set++
			}
		}
		if set != 1 {
			return nil, fmt.Errorf("dns: rule %q needs exactly one of suffix, exact or contains", r.Name)
		}
		if r.Name == "" {
			r.Name = "dns-" + r.Suffix + r.Exact + r.Contains
		}
		if r.Severity == "" {
			r.Severity = "high"
		}
		if !severities[r.Severity] {
			return nil, fmt.Errorf("dns: %q: severity %q is not low, medium, high or critical", r.Name, r.Severity)
		}
		if err := name("dns", r.Name); err != nil {
			return nil, err
		}
		c.DNS = append(c.DNS, r)
	}
	if d.Baselines != nil {
		if err := d.Baselines.validate(); err != nil {
			return nil, err
		}
		c.Baselines = d.Baselines
	}
	for _, x := range d.ExecAllow {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" {
			return nil, errors.New("exec_allow: empty entry would allow every process")
		}
		c.ExecAllow = append(c.ExecAllow, x)
	}
	for _, t := range d.Thresholds {
		if t.Name == "" {
			return nil, errors.New("thresholds: every rule needs a name")
		}
		if !metrics[t.Metric] {
			return nil, fmt.Errorf("thresholds: %q: unknown metric %q", t.Name, t.Metric)
		}
		switch t.Op {
		case "":
			t.Op = ">"
		case ">", ">=":
		default:
			return nil, fmt.Errorf("thresholds: %q: op %q is not > or >=", t.Name, t.Op)
		}
		if math.IsNaN(t.Value) || math.IsInf(t.Value, 0) || t.Value < 0 {
			return nil, fmt.Errorf("thresholds: %q: value must be a finite number, zero or more", t.Name)
		}
		if t.Window == 0 {
			t.Window = DefaultWindow
		}
		if t.Window < minWindow || t.Window > maxWindow {
			return nil, fmt.Errorf("thresholds: %q: window %s is outside %s to %s", t.Name, t.Window, minWindow, maxWindow)
		}
		if t.Severity == "" {
			t.Severity = "medium"
		}
		if !severities[t.Severity] {
			return nil, fmt.Errorf("thresholds: %q: severity %q is not low, medium, high or critical", t.Name, t.Severity)
		}
		if err := name("thresholds", t.Name); err != nil {
			return nil, err
		}
		c.Thresholds = append(c.Thresholds, t)
	}
	return c, nil
}

// MatchPort returns the first port rule for a destination port and protocol. A
// rule with no proto is a TCP rule, as it was before UDP was seen at all.
func (c *Config) MatchPort(port uint16, proto string) (PortRule, bool) {
	return c.MatchPortDir(port, proto, "out")
}

// MatchPortDir is MatchPort for a connect the VM made ("out") or one made to it ("in"). A rule with no dir
// means "out", so a rule written before inbound connects were visible still means what it did.
func (c *Config) MatchPortDir(port uint16, proto, dir string) (PortRule, bool) {
	if c == nil || port == 0 {
		return PortRule{}, false
	}
	if proto == "" {
		proto = "tcp"
	}
	if dir == "" {
		dir = "out"
	}
	for _, r := range c.Ports {
		rdir := r.Dir
		if rdir == "" {
			rdir = "out"
		}
		if r.Port == port && (r.Proto == "any" || r.Proto == proto || (r.Proto == "" && proto == "tcp")) && (rdir == "any" || rdir == dir) {
			return r, true
		}
	}
	return PortRule{}, false
}

// MatchDNS returns the first DNS rule that a looked-up name matches.
func (c *Config) MatchDNS(name string) (DNSRule, bool) {
	if c == nil || name == "" {
		return DNSRule{}, false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, r := range c.DNS {
		if r.matches(name) {
			return r, true
		}
	}
	return DNSRule{}, false
}

// AllowsExec reports whether comm starts with an operator-allowed name. The
// built-in QEMU thread names are checked separately and stay allowed.
func (c *Config) AllowsExec(comm string) bool {
	if c == nil {
		return false
	}
	comm = strings.ToLower(strings.TrimSpace(comm))
	for _, p := range c.ExecAllow {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// MaxWindow is the longest window among the threshold rules.
func (c *Config) MaxWindow() time.Duration {
	var m time.Duration
	if c == nil {
		return m
	}
	for _, t := range c.Thresholds {
		m = max(m, t.Window)
	}
	return m
}
