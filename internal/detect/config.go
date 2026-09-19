package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

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
)

var metrics = map[string]bool{
	MetricBlockReadP99MS: true, MetricBlockWriteP99MS: true, MetricWakeupDelayMS: true,
	MetricKVMExitsPerSec: true, MetricRetransmitsPerSec: true,
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
	Port     uint16 `yaml:"port"`
	Severity string `yaml:"severity"`
	Name     string `yaml:"name"`
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
	Watch      *Watchlist
	Ports      []PortRule
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
	Suppress     *time.Duration `yaml:"suppress"`
	Destinations []Rule         `yaml:"destinations"`
	Ports        []PortRule     `yaml:"ports"`
	ExecAllow    []string       `yaml:"exec_allow"`
	Thresholds   []Threshold    `yaml:"thresholds"`
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

// MatchPort returns the first port rule for a destination port.
func (c *Config) MatchPort(port uint16) (PortRule, bool) {
	if c == nil || port == 0 {
		return PortRule{}, false
	}
	for _, r := range c.Ports {
		if r.Port == port {
			return r, true
		}
	}
	return PortRule{}, false
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
