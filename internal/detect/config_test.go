package detect

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const fullDoc = `
suppress: 2m
destinations:
  - cidr: 185.0.0.0/8
    name: unexpected-egress
ports:
  - port: 25
    name: smtp
    severity: medium
  - port: 6667
exec_allow: [" Backup-Agent ", node_exporter]
thresholds:
  - name: slow-disk
    metric: block_write_p99_ms
    value: 50
  - name: exit-storm
    metric: kvm_exits_per_sec
    op: ">="
    value: 200000
    window: 1m
    severity: high
`

func TestParseFullDocument(t *testing.T) {
	c, err := Parse([]byte(fullDoc))
	if err != nil {
		t.Fatal(err)
	}
	if c.Suppress != 2*time.Minute {
		t.Fatalf("suppress %s", c.Suppress)
	}
	if r, ok := c.Watch.Match(parseIP("185.1.1.1")); !ok || r.Severity != "high" {
		t.Fatalf("watch %+v %v", r, ok)
	}
	if r, ok := c.MatchPort(25, "tcp"); !ok || r.Name != "smtp" || r.Severity != "medium" {
		t.Fatalf("port %+v", r)
	}
	if r, ok := c.MatchPort(6667, "tcp"); !ok || r.Name != "port-6667" || r.Severity != "high" {
		t.Fatalf("default port rule %+v", r)
	}
	if _, ok := c.MatchPort(80, "tcp"); ok {
		t.Fatal("port 80 matched")
	}
	if !c.AllowsExec("backup-agent-2") || !c.AllowsExec("NODE_EXPORTER") || c.AllowsExec("nc") {
		t.Fatalf("exec_allow %v", c.ExecAllow)
	}
	a, b := c.Thresholds[0], c.Thresholds[1]
	if a.Op != ">" || a.Window != DefaultWindow || a.Severity != "medium" {
		t.Fatalf("threshold defaults %+v", a)
	}
	if b.Op != ">=" || b.Window != time.Minute || b.Severity != "high" {
		t.Fatalf("threshold %+v", b)
	}
	if c.MaxWindow() != time.Minute {
		t.Fatalf("max window %s", c.MaxWindow())
	}
}

func TestParseEmptyIsDefault(t *testing.T) {
	for _, in := range []string{"", "\n", "# only a comment\n"} {
		c, err := Parse([]byte(in))
		if err != nil || c.Suppress != DefaultSuppress || c.Watch == nil || len(c.Thresholds) != 0 {
			t.Fatalf("%q: %+v %v", in, c, err)
		}
	}
}

func TestSuppressZeroTurnsItOff(t *testing.T) {
	c, err := Parse([]byte("suppress: 0s\n"))
	if err != nil || c.Suppress != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key (a typo would disable a rule)": "threshold:\n  - name: x\n",
		"unknown field in a rule":                             "ports:\n  - port: 25\n    sevrity: high\n",
		"bad cidr":                                            "destinations:\n  - cidr: nope\n",
		"bad destination severity":                            "destinations:\n  - cidr: 1.2.3.4\n    severity: urgent\n",
		"port zero":                                           "ports:\n  - name: x\n",
		"port too big":                                        "ports:\n  - port: 70000\n",
		"duplicate names":                                     "ports:\n  - {port: 1, name: a}\n  - {port: 2, name: a}\n",
		"empty exec_allow entry":                              "exec_allow: ['  ']\n",
		"negative suppress":                                   "suppress: -1m\n",
		"threshold without name":                              "thresholds:\n  - metric: wakeup_delay_ms\n    value: 1\n",
		"unknown metric":                                      "thresholds:\n  - {name: x, metric: cpu_steal, value: 1}\n",
		"bad op":                                              "thresholds:\n  - {name: x, metric: wakeup_delay_ms, op: '<', value: 1}\n",
		"negative value":                                      "thresholds:\n  - {name: x, metric: wakeup_delay_ms, value: -1}\n",
		"window too short":                                    "thresholds:\n  - {name: x, metric: wakeup_delay_ms, value: 1, window: 1s}\n",
		"window too long":                                     "thresholds:\n  - {name: x, metric: wakeup_delay_ms, value: 1, window: 2h}\n",
		"bad threshold severity":                              "thresholds:\n  - {name: x, metric: wakeup_delay_ms, value: 1, severity: loud}\n",
	}
	for why, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted: %s\n%s", why, in)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("empty error for: %s", why)
		}
	}
}

func TestParseErrorDoesNotNameInternalTypes(t *testing.T) {
	_, err := Parse([]byte("threshold: []\n"))
	if err == nil || strings.Contains(err.Error(), "detect.doc") || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("%v", err)
	}
}

// The deploy script copies this file to every host, so it has to parse, both as
// shipped and with its commented-out examples switched on.
func TestShippedExampleParses(t *testing.T) {
	raw, err := os.ReadFile("../../configs/detections.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("as shipped: %v", err)
	}
	if _, ok := c.Watch.Match(parseIP("185.1.2.3")); !ok {
		t.Fatal("the shipped destination rule does not match")
	}

	var on []string
	live := false
	for _, line := range strings.Split(string(raw), "\n") {
		body, isComment := strings.CutPrefix(line, "# ")
		switch {
		case isComment && regexp.MustCompile(`^(suppress|ports|exec_allow|thresholds):`).MatchString(body):
			live = true
			on = append(on, body)
		case live && strings.HasPrefix(line, "#  "):
			on = append(on, strings.TrimPrefix(line, "#"))
		default:
			live = false
			if !isComment && !strings.HasPrefix(line, "#") {
				on = append(on, line)
			}
		}
	}
	full, err := Parse([]byte(strings.Join(on, "\n")))
	if err != nil {
		t.Fatalf("with examples enabled: %v\n%s", err, strings.Join(on, "\n"))
	}
	if len(full.Ports) != 3 || full.Ports[1].Proto != "udp" || full.Ports[2].Dir != "in" || len(full.Thresholds) != 1 || len(full.ExecAllow) != 1 || full.Suppress != DefaultSuppress {
		t.Fatalf("%+v", full)
	}
}

func TestPortRulesMatchByProtocol(t *testing.T) {
	c, err := Parse([]byte(`
ports:
  - {port: 25, name: smtp}
  - {port: 53, name: dns-udp, proto: udp}
  - {port: 123, name: ntp-any, proto: any}
  - {port: 443, name: https, proto: tcp}
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		port  uint16
		proto string
		want  string
	}{
		{25, "tcp", "smtp"}, {25, "udp", ""}, // no proto means TCP, as it always did
		{25, "", "smtp"}, // an event with no protocol is a host connect, which is TCP
		{53, "udp", "dns-udp"}, {53, "tcp", ""},
		{123, "udp", "ntp-any"}, {123, "tcp", "ntp-any"},
		{443, "tcp", "https"}, {443, "udp", ""},
		{9999, "udp", ""},
	} {
		r, ok := c.MatchPort(x.port, x.proto)
		if (x.want == "") == ok || (ok && r.Name != x.want) {
			t.Errorf("%d/%s: got %q ok=%v, want %q", x.port, x.proto, r.Name, ok, x.want)
		}
	}
	if c.Ports[0].Proto != "tcp" {
		t.Fatalf("the default proto is %q", c.Ports[0].Proto)
	}
	if _, err := Parse([]byte("ports:\n  - {port: 53, proto: icmp}\n")); err == nil {
		t.Fatal("an unknown proto was accepted")
	}
}

func TestPortRulesMatchByDirectionAndDefaultToOut(t *testing.T) {
	c, err := Parse([]byte(`
ports:
  - {port: 25, name: smtp-out}
  - {port: 22, name: ssh-in, dir: in}
  - {port: 3389, name: rdp-any, dir: any}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Ports[0].Dir != "out" {
		t.Fatalf("a rule with no dir must mean out, as it always did: %q", c.Ports[0].Dir)
	}
	for _, x := range []struct {
		port      uint16
		dir, want string
	}{
		{25, "out", "smtp-out"}, {25, "in", ""}, // a connect INTO the guest on 25 is not the guest sending mail
		{22, "in", "ssh-in"}, {22, "out", ""},
		{3389, "out", "rdp-any"}, {3389, "in", "rdp-any"},
		{25, "", "smtp-out"}, // no direction is out
	} {
		r, ok := c.MatchPortDir(x.port, "tcp", x.dir)
		if (x.want == "") == ok || (ok && r.Name != x.want) {
			t.Errorf("%d %q: got %q ok=%v, want %q", x.port, x.dir, r.Name, ok, x.want)
		}
	}
	// MatchPort is the outbound question.
	if _, ok := c.MatchPort(22, "tcp"); ok {
		t.Fatal("an inbound-only rule matched an outbound connect")
	}
	if _, err := Parse([]byte("ports:\n  - {port: 22, dir: sideways}\n")); err == nil || !strings.Contains(err.Error(), "dir") {
		t.Fatalf("a bad dir was accepted: %v", err)
	}
}
