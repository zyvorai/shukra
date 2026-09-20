package detect

import (
	"github.com/zyvorai/shukra/internal/baseline"
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
		"dns rule with no match":                              "dns:\n  - name: x\n",
		"dns rule with two matches":                           "dns:\n  - {name: x, suffix: a.com, exact: b.com}\n",
		"dns bad severity":                                    "dns:\n  - {name: x, suffix: a.com, severity: loud}\n",
		"dns unknown field":                                   "dns:\n  - {name: x, sufix: a.com}\n",
		"dns duplicate names":                                 "dns:\n  - {name: x, suffix: a.com}\n  - {name: x, exact: b.com}\n",
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
		case isComment && regexp.MustCompile(`^(suppress|ports|dns|baselines|responses|guardrails|exec_allow|thresholds):`).MatchString(body):
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
	if len(full.Ports) != 3 || full.Ports[1].Proto != "udp" || full.Ports[2].Dir != "in" || len(full.DNS) != 2 || full.Baselines == nil || len(full.Responses) != 1 || full.Guard.MaxPerHour != 3 || len(full.Guard.NeverIsolate) != 1 || full.Baselines.Learn != 24*time.Hour || len(full.Thresholds) != 1 || len(full.ExecAllow) != 1 || full.Suppress != DefaultSuppress {
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

func TestDNSRulesMatchOnLabelBoundariesAndIgnoreCase(t *testing.T) {
	c, err := Parse([]byte(`
dns:
  - {name: pool, suffix: .Nanopool.ORG.}
  - {name: exact, exact: Login.Example.com}
  - {name: word, contains: PASTEBIN, severity: low}
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		name string
		rule string
	}{
		{"nanopool.org", "pool"},
		{"eth.NANOPOOL.org", "pool"},
		{"a.b.nanopool.org.", "pool"},
		{"badnanopool.org", ""}, // not on a label boundary
		{"nanopool.org.evil.com", ""},
		{"login.example.com", "exact"},
		{"x.login.example.com", ""}, // exact means exact
		{"my-pastebin-mirror.net", "word"},
		{"example.com", ""},
		{"", ""},
	} {
		r, ok := c.MatchDNS(x.name)
		if x.rule == "" && ok || x.rule != "" && (!ok || r.Name != x.rule) {
			t.Errorf("%q: got %+v %v, want rule %q", x.name, r, ok, x.rule)
		}
	}
	if r, _ := c.MatchDNS("pastebin.com"); r.Severity != "low" {
		t.Errorf("severity: %+v", r)
	}
	if r, _ := c.MatchDNS("nanopool.org"); r.Severity != "high" {
		t.Errorf("a rule with no severity is high: %+v", r)
	}
	if _, ok := (*Config)(nil).MatchDNS("nanopool.org"); ok {
		t.Error("a nil config matched")
	}
}

func TestBaselinesAreOffUnlessTheSectionIsThere(t *testing.T) {
	c, err := Parse([]byte("suppress: 1m\n"))
	if err != nil || c.Baselines != nil {
		t.Fatalf("%v %+v", err, c.Baselines)
	}
	if (*BaselineConfig)(nil).Learns(baseline.Destination) {
		t.Fatal("a nil config learns nothing")
	}
}

func TestBaselinesGetTheirDefaultsAndTheKindsAndSeveritiesAreWhatWasAsked(t *testing.T) {
	c, err := Parse([]byte("baselines:\n  learn: 24h\n"))
	if err != nil || c.Baselines == nil {
		t.Fatalf("%v %+v", err, c.Baselines)
	}
	b := c.Baselines
	o := b.Options()
	if o.Learn != 24*time.Hour || o.MaxAlertsPerDay != 20 || o.MaxItems != 2048 || o.MaxAge != 720*time.Hour {
		t.Fatalf("%+v", o)
	}
	for _, k := range baseline.Kinds {
		if !b.Learns(k) {
			t.Errorf("%s is learned by default", k)
		}
	}
	if b.SeverityOf(baseline.DNSSuffix) != "low" || b.SeverityOf(baseline.Destination) != "medium" || b.SeverityOf(baseline.InboundPeer) != "medium" {
		t.Fatal("default severities")
	}
	c, err = Parse([]byte("baselines:\n  learn: 2h\n  kinds: [dns-suffix]\n  severity: {dns-suffix: high}\n  max_alerts_per_day: 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	b = c.Baselines
	if b.Learns(baseline.Destination) || !b.Learns(baseline.DNSSuffix) || b.SeverityOf(baseline.DNSSuffix) != "high" || b.Options().MaxAlertsPerDay != 5 {
		t.Fatalf("%+v", b)
	}
}

func TestBaselinesRejectWhatWouldQuietlyDoNothingOrEverything(t *testing.T) {
	for why, in := range map[string]string{
		"learn too short":        "baselines:\n  learn: 10s\n",
		"learn too long":         "baselines:\n  learn: 2400h\n",
		"max age under learn":    "baselines:\n  learn: 48h\n  max_age: 24h\n",
		"unknown kind":           "baselines:\n  kinds: [destinations]\n",
		"repeated kind":          "baselines:\n  kinds: [destination, destination]\n",
		"severity for a nonkind": "baselines:\n  severity: {exec: high}\n",
		"bad severity":           "baselines:\n  severity: {destination: loud}\n",
		"cap below one":          "baselines:\n  max_alerts_per_day: -1\n",
		"cap too large":          "baselines:\n  max_alerts_per_day: 5000\n",
		"items too small":        "baselines:\n  max_items: 3\n",
		"unknown field":          "baselines:\n  lern: 24h\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted: %s\n%s", why, in)
		}
	}
}

func TestNoResponsesUnlessTheFileHasThemAndGuardrailsHaveDefaults(t *testing.T) {
	c, err := Parse([]byte("suppress: 1m\n"))
	if err != nil || len(c.Responses) != 0 || c.Guard.MaxPerHour != 3 || len(c.Guard.NeverIsolate) != 0 {
		t.Fatalf("%v %+v %+v", err, c.Responses, c.Guard)
	}
}

func TestAResponseGetsSafeDefaultsProposesByDefaultAndKeepsWhatWasAsked(t *testing.T) {
	c, err := Parse([]byte(`
responses:
  - name: ask
    action: isolate
    rules: [crypto-pool]
  - name: auto
    action: isolate
    mode: enforce
    rules: [new-destination, crypto-pool]
    min_severity: medium
    release_after: 15m
    cooldown: 2h
    expire: 10m
  - name: broad
    action: isolate
guardrails:
  never_isolate: [db-primary]
  max_per_hour: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	ask, auto, broad := c.Responses[0], c.Responses[1], c.Responses[2]
	if ask.Mode != "propose" || ask.Cooldown != time.Hour || ask.Expire != 30*time.Minute || ask.ReleaseAfter != 0 || ask.MinSeverity != "" {
		t.Fatalf("a response proposes by default, with a cooldown and an expiry: %+v", ask)
	}
	if auto.Mode != "enforce" || auto.ReleaseAfter != 15*time.Minute || auto.Cooldown != 2*time.Hour || auto.Expire != 10*time.Minute || auto.MinSeverity != "medium" {
		t.Fatalf("%+v", auto)
	}
	if broad.MinSeverity != "high" || broad.Mode != "propose" {
		t.Fatalf("with no rules named, only high detections and only a proposal: %+v", broad)
	}
	if c.Guard.MaxPerHour != 5 || len(c.Guard.NeverIsolate) != 1 || c.Guard.NeverIsolate[0] != "db-primary" {
		t.Fatalf("%+v", c.Guard)
	}
}

func TestAResponseAnswersARuleAtOrAboveItsSeverityAndNothingElse(t *testing.T) {
	named := Response{Rules: []string{"a", "b"}}
	if !named.Answers("a", "low") || !named.Answers("b", "critical") || named.Answers("c", "critical") {
		t.Fatal("a response with rules answers those rules at any severity")
	}
	named.MinSeverity = "high"
	if named.Answers("a", "medium") || !named.Answers("a", "high") || !named.Answers("a", "critical") {
		t.Fatal("severity is a floor")
	}
	any := Response{MinSeverity: "high"}
	if any.Answers("x", "medium") || !any.Answers("x", "high") {
		t.Fatal("no rules means any rule, at the floor")
	}
	if !SeverityAtLeast("critical", "high") || SeverityAtLeast("low", "medium") || SeverityAtLeast("bogus", "low") {
		t.Fatal("severity order")
	}
}

func TestResponsesRejectWhatWouldActTooWidelyOrNotAtAll(t *testing.T) {
	for why, in := range map[string]string{
		"no name":                  "responses:\n  - action: isolate\n",
		"no action":                "responses:\n  - name: x\n",
		"another action":           "responses:\n  - {name: x, action: kill}\n",
		"bad mode":                 "responses:\n  - {name: x, action: isolate, mode: auto}\n",
		"enforce on any detection": "responses:\n  - {name: x, action: isolate, mode: enforce}\n",
		"empty rule name":          "responses:\n  - {name: x, action: isolate, rules: ['']}\n",
		"bad severity":             "responses:\n  - {name: x, action: isolate, min_severity: urgent}\n",
		"release after too short":  "responses:\n  - {name: x, action: isolate, release_after: 10s}\n",
		"release after too long":   "responses:\n  - {name: x, action: isolate, release_after: 48h}\n",
		"cooldown too short":       "responses:\n  - {name: x, action: isolate, cooldown: 10s}\n",
		"expire too long":          "responses:\n  - {name: x, action: isolate, expire: 72h}\n",
		"duplicate name":           "responses:\n  - {name: x, action: isolate}\n  - {name: x, action: isolate}\n",
		"unknown field":            "responses:\n  - {name: x, action: isolate, rule: [a]}\n",
		"empty protected name":     "guardrails:\n  never_isolate: ['']\n",
		"max per hour negative":    "guardrails:\n  max_per_hour: -1\n",
		"max per hour too large":   "guardrails:\n  max_per_hour: 500\n",
		"unknown guardrail":        "guardrails:\n  max_a_day: 1\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted: %s\n%s", why, in)
		}
	}
	// A dry run on any detection is harmless, and is allowed to try a wide rule out before it is narrowed.
	if _, err := Parse([]byte("responses:\n  - {name: x, action: isolate, mode: enforce, dry_run: true}\n")); err != nil {
		t.Fatalf("a wide dry run is how a response is tried out: %v", err)
	}
	// A response may share a name with the rule it answers.
	if _, err := Parse([]byte("ports:\n  - {port: 25, name: smtp}\nresponses:\n  - {name: smtp, action: isolate, rules: [smtp]}\n")); err != nil {
		t.Fatal(err)
	}
}
