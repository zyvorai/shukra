package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/zyvorai/shukra/internal/identity"
)

func byID(checks []Check, id string) *Check {
	for i := range checks {
		if checks[i].ID == id {
			return &checks[i]
		}
	}
	return nil
}

// healthy is a well-configured daemon, so each test can break one thing.
func healthy(t *testing.T) *State {
	t.Helper()
	st := New("node-07")
	st.kernelRelease = func() string { return "6.8.0-139-generic" }
	st.SetConfig(ConfigInfo{
		Listen: "127.0.0.1:30970", KeyLen: 32, ReadOnlyKey: true, DataDir: "/var/lib/shukra",
		Sinks: []string{"webhook"}, IsolateAllow: []string{"10.0.0.0/24"}, RulesFile: "/etc/shukra/detections.yaml",
	})
	st.SetPrograms([]Program{
		{Name: "kvm", Status: "attached", Detail: "4 hooks"}, {Name: "sched", Status: "attached", Detail: "4 hooks"},
		{Name: "block", Status: "attached", Detail: "2 hooks"}, {Name: "net", Status: "attached", Detail: "3 hooks"},
		{Name: "tap", Status: "attached", Detail: "2 taps, enforcement survives a daemon restart"},
	})
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	f := newFake()
	f.durable = true
	st.SetEnforcer(f)
	return st
}

func TestAWellConfiguredDaemonHasNothingToFix(t *testing.T) {
	for _, c := range healthy(t).Doctor() {
		if c.Status != "ok" {
			t.Fatalf("%+v", c)
		}
	}
}

func TestTheHostThatWasDeployed_DevKeyPlainHTTPOnAPublicAddress(t *testing.T) {
	st := healthy(t)
	st.SetConfig(ConfigInfo{Listen: "0.0.0.0:30970", DevKey: true, KeyLen: 6, DataDir: "/var/lib/shukra", RulesFile: "/etc/shukra/detections.yaml"})
	checks := st.Doctor()
	auth, transport := byID(checks, "auth"), byID(checks, "transport")
	if auth.Status != "fail" || !strings.Contains(auth.Fix, "openssl rand") {
		t.Fatalf("%+v", auth)
	}
	// Plain HTTP alone is a warning. With the well-known key on top, it is a failure.
	if transport.Status != "fail" || !strings.Contains(transport.Fix, "-tls-cert") {
		t.Fatalf("%+v", transport)
	}
	if checks[0].Status != "fail" {
		t.Fatalf("the worst finding must come first: %+v", checks[0])
	}
}

func TestExposureIsJudgedByWhoCanReachIt(t *testing.T) {
	cases := []struct {
		name        string
		cfg         ConfigInfo
		auth, trans string
	}{
		{"real key, loopback", ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32}, "ok", "ok"},
		{"real key, public, plain", ConfigInfo{Listen: "0.0.0.0:1", KeyLen: 32}, "ok", "warn"},
		{"real key, public, tls", ConfigInfo{Listen: "0.0.0.0:1", KeyLen: 32, TLS: true}, "ok", "ok"},
		{"dev key, loopback", ConfigInfo{Listen: "[::1]:1", DevKey: true, KeyLen: 6}, "warn", "ok"},
		{"dev key, public", ConfigInfo{Listen: "0.0.0.0:1", DevKey: true, KeyLen: 6, TLS: true}, "fail", "ok"},
		{"short key", ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 8}, "warn", "ok"},
		{"no auth, loopback", ConfigInfo{Listen: "localhost:1", NoAuth: true}, "fail", "ok"},
		{"no auth, public", ConfigInfo{Listen: ":30970", NoAuth: true}, "fail", "fail"},
	}
	for _, c := range cases {
		st := healthy(t)
		st.SetConfig(c.cfg)
		checks := st.Doctor()
		if a, tr := byID(checks, "auth").Status, byID(checks, "transport").Status; a != c.auth || tr != c.trans {
			t.Errorf("%s: auth %s transport %s, want %s %s", c.name, a, tr, c.auth, c.trans)
		}
	}
}

// ConfigInfo carries only whether the key is the dev key and how long it is, never
// the key, so the audit has nothing secret to print. A real key must add no
// key-shaped text at all.
func TestARealKeyProducesNoKeyText(t *testing.T) {
	st := healthy(t)
	st.SetConfig(ConfigInfo{Listen: "0.0.0.0:1", KeyLen: 32, TLS: true, ReadOnlyKey: true, DataDir: "/d", Sinks: []string{"file"}, RulesFile: "/r"})
	if got := byID(st.Doctor(), "auth"); got.Status != "ok" || got.Detail != "" || got.Fix != "" {
		t.Fatalf("%+v", got)
	}
}

func TestKernelAgeExplainsWhatIsUnavailable(t *testing.T) {
	for rel, want := range map[string]string{
		"4.19.0-generic": "warn", "5.7.9": "warn", "5.10.0-28-amd64": "info", "6.5.0": "info",
		"6.6.0": "ok", "6.8.0-139-generic": "ok", "6.17.1+deb13": "ok", "7.0.0": "ok",
	} {
		st := healthy(t)
		st.kernelRelease = func() string { return rel }
		if got := byID(st.Doctor(), "kernel").Status; got != want {
			t.Errorf("%s: %s, want %s", rel, got, want)
		}
	}
	st := healthy(t)
	st.kernelRelease = func() string { return "" }
	if byID(st.Doctor(), "kernel") != nil {
		t.Fatal("an unreadable kernel version produced a finding about it")
	}
}

func TestDetachedAndPartialProgramsAreReportedWithTheirReason(t *testing.T) {
	st := healthy(t)
	st.SetPrograms([]Program{
		{Name: "kvm", Status: "attached", Detail: "3/4 hooks; tracepoint/kvm/kvm_pio: no such file"},
		{Name: "net", Status: "detached", Detail: "operation not permitted"},
		{Name: "tap", Status: "detached", Detail: "no VM tap interfaces to attach to yet"},
		{Name: "sched", Status: "attached", Detail: "4 hooks"},
	})
	checks := st.Doctor()
	if c := byID(checks, "program-kvm"); c == nil || c.Status != "warn" || !strings.Contains(c.Title, "partly") {
		t.Fatalf("%+v", c)
	}
	if c := byID(checks, "program-net"); c == nil || c.Status != "warn" || !strings.Contains(c.Detail, "operation not permitted") {
		t.Fatalf("%+v", c)
	}
	// No VM tap yet is a state of the host, not a fault.
	if c := byID(checks, "program-tap"); c == nil || c.Status != "info" {
		t.Fatalf("%+v", c)
	}
	if byID(checks, "program-sched") != nil {
		t.Fatal("a healthy program got a finding")
	}
}

func TestVMsTheTapProgramCannotSee(t *testing.T) {
	st := healthy(t)
	var vms []identity.VM
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		vms = append(vms, identity.VM{Name: n})
	}
	vms = append(vms, identity.VM{Name: "seen", Taps: []string{"tap9"}})
	st.SetVMs(vms)
	c := byID(st.Doctor(), "blind-vms")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "7 of 8 VMs") || !strings.Contains(c.Detail, "and 2 more") || !strings.Contains(c.Fix, "CAP_SYS_PTRACE") {
		t.Fatalf("%+v", c)
	}
	// With the tap program not attached the same fact is information, not a warning.
	st.SetPrograms([]Program{{Name: "tap", Status: "detached", Detail: "TCX needs Linux 6.6 or newer"}})
	if c := byID(st.Doctor(), "blind-vms"); c.Status != "info" {
		t.Fatalf("%+v", c)
	}
	st.SetVMs([]identity.VM{{Name: "x", Taps: []string{"t"}}})
	if byID(st.Doctor(), "blind-vms") != nil {
		t.Fatal("no blind VMs, but a finding")
	}
}

func TestIsolateStates(t *testing.T) {
	st := healthy(t)
	if c := byID(st.Doctor(), "isolate"); c.Status != "ok" || !strings.Contains(c.Detail, "10.0.0.1/32") {
		t.Fatalf("%+v", c)
	}
	f := newFake()
	f.ok, f.why = false, "no management allow list is configured"
	st.SetConfig(ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32})
	st.SetEnforcer(f)
	if c := byID(st.Doctor(), "isolate"); c.Status != "info" || !strings.Contains(c.Fix, "-isolate-allow") {
		t.Fatalf("not configured: %+v", c)
	}
	// Configured but not working is a warning: the operator asked for it.
	st.SetConfig(ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32, IsolateAllow: []string{"10.0.0.0/24"}})
	f.why = "the tap program is not loaded"
	if c := byID(st.Doctor(), "isolate"); c.Status != "warn" {
		t.Fatalf("configured but unavailable: %+v", c)
	}
	f2 := newFake()
	f2.durable = false
	st.SetEnforcer(f2)
	if c := byID(st.Doctor(), "isolate"); c.Status != "warn" || !strings.Contains(c.Title, "not survive") {
		t.Fatalf("unpinned: %+v", c)
	}
	st.SetEnforcer(nil)
	if c := byID(st.Doctor(), "isolate"); c.Status != "info" {
		t.Fatalf("no enforcer: %+v", c)
	}
}

func TestPersistenceAlertsAndRules(t *testing.T) {
	st := healthy(t)
	st.SetConfig(ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32})
	checks := st.Doctor()
	if byID(checks, "persistence").Status != "warn" || byID(checks, "alerts").Status != "info" || byID(checks, "rules").Status != "info" {
		t.Fatalf("%+v %+v %+v", byID(checks, "persistence"), byID(checks, "alerts"), byID(checks, "rules"))
	}
	st.SetConfig(ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32, DataDir: "/var/lib/shukra", Sinks: []string{"webhook", "file"}, RulesFile: "/etc/shukra/detections.yaml"})
	checks = st.Doctor()
	if !strings.Contains(byID(checks, "alerts").Title, "webhook, file") || byID(checks, "rules").Status != "ok" {
		t.Fatalf("%+v", byID(checks, "alerts"))
	}
	// A failed reload keeps the old rules, which the operator may not realise.
	st.SetRulesStatus(errors.New(`line 3: field threshold not found`))
	c := byID(st.Doctor(), "rules")
	if c.Status != "fail" || !strings.Contains(c.Detail, "previous rules are still in force") || !strings.Contains(c.Fix, "rules check") {
		t.Fatalf("%+v", c)
	}
	st.SetRulesStatus(nil)
	if byID(st.Doctor(), "rules").Status != "ok" {
		t.Fatal("a successful reload did not clear the finding")
	}
}

func TestUnreadyDaemonIsFlagged(t *testing.T) {
	st := New("n")
	st.kernelRelease = func() string { return "6.8.0" }
	st.SetConfig(ConfigInfo{Listen: "127.0.0.1:1", KeyLen: 32})
	if byID(st.Doctor(), "scan") == nil {
		t.Fatal("no finding before the first scan")
	}
}

func TestFindingsAreOrderedWorstFirst(t *testing.T) {
	st := healthy(t)
	st.SetConfig(ConfigInfo{Listen: "0.0.0.0:1", DevKey: true, KeyLen: 6})
	prev := 4
	for _, c := range st.Doctor() {
		if r := statusRank[c.Status]; r > prev {
			t.Fatalf("%s after a milder finding", c.Status)
		} else {
			prev = r
		}
	}
}

func TestProgramsDetachedForTheSameReasonAreOneFinding(t *testing.T) {
	st := healthy(t)
	same := "CO-RE objects are not linked in this binary."
	st.SetPrograms([]Program{
		{Name: "kvm", Status: "detached", Detail: same}, {Name: "sched", Status: "detached", Detail: same},
		{Name: "block", Status: "detached", Detail: same}, {Name: "net", Status: "detached", Detail: "operation not permitted"},
		{Name: "tap", Status: "attached", Detail: "1 taps"},
	})
	checks := st.Doctor()
	group := byID(checks, "programs-detached")
	if group == nil || !strings.HasPrefix(group.Title, "3 programs are detached (kvm, sched, block)") || group.Detail != same {
		t.Fatalf("%+v", group)
	}
	// A program with its own reason keeps its own finding.
	if one := byID(checks, "program-net"); one == nil || one.Detail != "operation not permitted" {
		t.Fatalf("%+v", one)
	}
	for _, id := range []string{"program-kvm", "program-sched", "program-block"} {
		if byID(checks, id) != nil {
			t.Fatalf("%s was reported on its own as well as in the group", id)
		}
	}
}

func withTapsTraced(st *State, names ...string) {
	st.SetTapSource(func() []TapStat {
		var out []TapStat
		for _, n := range names {
			out = append(out, TapStat{Name: n})
		}
		return out
	})
}

func TestAVMWhoseTapIsInAnotherNamespaceIsNamedNotSilentlyUncovered(t *testing.T) {
	st := healthy(t)
	st.SetVMs([]identity.VM{
		{Name: "db", Taps: []string{"tap0"}},
		{Name: "sandbox", Taps: []string{"eph718bb58b"}},
	})
	withTapsTraced(st, "tap0")
	st.linkExists = func(name string) bool { return name == "tap0" } // eph718bb58b is not in this namespace
	checks := st.Doctor()
	c := byID(checks, "vm-tap-other-netns")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "1 of 2 VMs") || !strings.Contains(c.Detail, "sandbox (eph718bb58b)") || strings.Contains(c.Detail, "db (") || !strings.Contains(c.Fix, "host veth") {
		t.Fatalf("%+v", c)
	}
	if byID(checks, "vm-tap-untraced") != nil {
		t.Fatal("a tap that is not here was reported as untraced")
	}
	if checks[0].Status != "warn" {
		t.Fatalf("the finding should rank first, got %+v", checks[0])
	}
}

func TestATapThatExistsButIsNotTracedIsInformationNotAWarning(t *testing.T) {
	st := healthy(t)
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}, {Name: "web", Taps: []string{"tap1"}}})
	withTapsTraced(st, "tap0")
	st.linkExists = func(string) bool { return true }
	checks := st.Doctor()
	c := byID(checks, "vm-tap-untraced")
	if c == nil || c.Status != "info" || !strings.HasPrefix(c.Title, "1 VMs") || !strings.Contains(c.Detail, "web (tap1)") || !strings.Contains(c.Detail, "next scan") {
		t.Fatalf("%+v", c)
	}
	if byID(checks, "vm-tap-other-netns") != nil {
		t.Fatal("a tap that is here was reported as in another namespace")
	}
}

func TestNoUncoveredTapFindingWhenThereIsNothingToCompareOrEverythingIsTraced(t *testing.T) {
	// Every tap traced: nothing to say.
	st := healthy(t)
	withTapsTraced(st, "tap0")
	st.linkExists = func(string) bool { return false }
	for _, c := range st.Doctor() {
		if strings.HasPrefix(c.ID, "vm-tap-") {
			t.Fatalf("%+v", c)
		}
	}
	// No tap source (an unknown, not an empty list): nothing to compare against.
	st = healthy(t)
	st.SetVMs([]identity.VM{{Name: "sandbox", Taps: []string{"eph1"}}})
	st.linkExists = func(string) bool { return false }
	if byID(st.Doctor(), "vm-tap-other-netns") != nil {
		t.Fatal("reported without knowing what is traced")
	}
	// The tap program is not attached at all: the programs finding covers that.
	st = healthy(t)
	st.SetVMs([]identity.VM{{Name: "sandbox", Taps: []string{"eph1"}}})
	withTapsTraced(st)
	st.linkExists = func(string) bool { return false }
	st.SetPrograms([]Program{{Name: "tap", Status: "detached", Detail: "TCX needs Linux 6.6 or newer"}})
	if byID(st.Doctor(), "vm-tap-other-netns") != nil {
		t.Fatal("reported while the tap program was detached")
	}
}

func TestManyVMsInAnotherNamespaceAreListedBriefly(t *testing.T) {
	st := healthy(t)
	var vms []identity.VM
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		vms = append(vms, identity.VM{Name: n, Taps: []string{"eph" + n}})
	}
	st.SetVMs(vms)
	withTapsTraced(st)
	st.linkExists = func(string) bool { return false }
	c := byID(st.Doctor(), "vm-tap-other-netns")
	if c == nil || !strings.HasPrefix(c.Title, "7 of 7 VMs") || !strings.Contains(c.Detail, "and 2 more") {
		t.Fatalf("%+v", c)
	}
}

// A program the operator turned off with a flag is not broken, and rebuilding would not bring it back: the fix
// says so. One that failed to attach still gets the rebuild advice.
func TestAProgramSwitchedOffOnPurposeIsNotToldToRebuild(t *testing.T) {
	st := healthy(t)
	st.SetPrograms([]Program{
		{Name: "vmm", Status: "detached", Detail: "turned off with -vmm-tripwires=false"},
		{Name: "net", Status: "detached", Detail: "operation not permitted"},
	})
	checks := st.Doctor()
	off := byID(checks, "program-vmm")
	if off == nil || off.Status != "warn" || strings.Contains(off.Fix, "rebuild") || !strings.Contains(off.Fix, "on purpose") {
		t.Fatalf("a deliberate switch-off must not be told to rebuild: %+v", off)
	}
	if broken := byID(checks, "program-net"); broken == nil || !strings.Contains(broken.Fix, "rebuild") {
		t.Fatalf("a program that failed to attach still gets the rebuild advice: %+v", broken)
	}
}

// Two programs off for the same reason are one finding, and it carries the same advice as one alone would.
func TestSeveralProgramsSwitchedOffAreOneFindingWithTheSameAdvice(t *testing.T) {
	st := healthy(t)
	why := "turned off with -example=false"
	st.SetPrograms([]Program{{Name: "vmm", Status: "detached", Detail: why}, {Name: "drops", Status: "detached", Detail: why}})
	g := byID(st.Doctor(), "programs-detached")
	if g == nil || strings.Contains(g.Fix, "rebuild") || !strings.Contains(g.Fix, "on purpose") {
		t.Fatalf("%+v", g)
	}
}
