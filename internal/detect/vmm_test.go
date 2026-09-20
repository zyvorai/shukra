package detect

import (
	"strings"
	"testing"
)

func sensitive(r *VMMRules, p string) string {
	m, ok := r.SensitivePath(p)
	if !ok {
		return ""
	}
	return m
}

func TestTheDefaultsCatchTheFilesAnIntruderInAVMMWouldGoFor(t *testing.T) {
	r := DefaultVMMRules()
	for p, want := range map[string]string{
		"/etc/shadow":                       "/etc/shadow",
		"/etc/shadow-":                      "/etc/shadow-",
		"/etc/gshadow":                      "/etc/gshadow",
		"/etc/sudoers":                      "/etc/sudoers",
		"/etc/sudoers.d/90-cloud":           "/etc/sudoers.d",
		"/etc/ssh/ssh_host_rsa_key":         "/etc/ssh",
		"/root/.ssh/authorized_keys":        "/root/.ssh",
		"/home/alice/.ssh/id_ed25519":       "/home/*/.ssh",
		"/proc/1234/mem":                    "/proc/*/mem",
		"/proc/self/mem":                    "/proc/*/mem",
		"/proc/1234/task/1240/mem":          "/proc/*/task/*/mem",
		"/proc/kcore":                       "/proc/kcore",
		"/var/run/docker.sock":              "/var/run/docker.sock",
		"/etc/shukra/env":                   "/etc/shukra",
		"/var/lib/shukra/baselines.json":    "/var/lib/shukra",
		"/var/lib/rancher/k3s/server/token": "/var/lib/rancher/k3s/server",
	} {
		if got := sensitive(r, p); got != want {
			t.Errorf("%s: matched %q, want %q", p, got, want)
		}
	}
}

func TestWhatAVMMOpensEveryDayIsNotSensitive(t *testing.T) {
	r := DefaultVMMRules()
	for _, p := range []string{
		"/dev/kvm", "/dev/net/tun", "/var/lib/libvirt/images/web.qcow2", "/proc/self/status", "/proc/1234/cmdline", "/proc/1234/task/9/comm",
		"/sys/devices/system/cpu/online", "/usr/share/qemu/bios.bin", "/etc/qemu/bridge.conf", "/etc/hosts", "/root/vm/disk.img", "/home/alice/vm.img",
		"/etc/ssh2/config",    // a different name that only starts the same
		"/etc/shadowed",       // likewise
		"/proc/1234/memory",   // not mem
		"/proc/mem",           // * is exactly one segment
		"/proc/1234/task/mem", // and not none
		"/etc",
	} {
		if m := sensitive(r, p); m != "" {
			t.Errorf("%s matched %q", p, m)
		}
	}
}

func TestAPathIsCleanedBeforeItIsJudgedSoTheUsualTricksDoNotHideIt(t *testing.T) {
	r := DefaultVMMRules()
	for _, p := range []string{"/etc/../etc/shadow", "/etc//shadow", "/etc/./shadow", "//etc/shadow", "/var/lib/../../etc/shadow", "/proc/self/../self/mem", "/etc/ssh/../ssh/sshd_config", "/etc/shadow/"} {
		if sensitive(r, p) == "" {
			t.Errorf("%s was not caught", p)
		}
	}
	if sensitive(r, "/etc/../etc/hosts") != "" {
		t.Error("a path that resolves to something harmless was reported")
	}
}

func TestARelativePathCannotBeJudgedAndIsNotReportedAsSensitive(t *testing.T) {
	r := DefaultVMMRules()
	for _, p := range []string{"shadow", "../etc/shadow", "./etc/shadow", "", "etc/shadow"} {
		if sensitive(r, p) != "" {
			t.Errorf("%q", p)
		}
	}
}

func TestIgnoreWinsOverTheDefaultsAndOverPaths(t *testing.T) {
	r, err := compileVMM(&VMMConfig{Paths: []string{"/srv/secret"}, Ignore: []string{"/root/.ssh/known_hosts", "/srv/secret/public", "/home/*/.ssh/config"}})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"/root/.ssh/known_hosts":  "",
		"/root/.ssh/id_rsa":       "/root/.ssh",
		"/srv/secret/key":         "/srv/secret",
		"/srv/secret/public/x":    "",
		"/home/bob/.ssh/config":   "",
		"/home/bob/.ssh/id_rsa":   "/home/*/.ssh",
		"/srv/secret/../secret/k": "/srv/secret",
		"/srv/secret/public/../k": "/srv/secret",
	} {
		if got := sensitive(r, p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestDefaultsFalseLeavesOnlyWhatTheFileNames(t *testing.T) {
	off := false
	r, err := compileVMM(&VMMConfig{Defaults: &off, Paths: []string{"/srv/secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if sensitive(r, "/etc/shadow") != "" || sensitive(r, "/srv/secret/x") == "" {
		t.Fatal("only the named path is sensitive")
	}
	on := true
	if r, _ = compileVMM(&VMMConfig{Defaults: &on}); sensitive(r, "/etc/shadow") == "" {
		t.Fatal("defaults: true is the default")
	}
	if r, _ = compileVMM(&VMMConfig{Defaults: &off}); sensitive(r, "/etc/shadow") != "" {
		t.Fatal("nothing at all is sensitive with defaults off and no paths")
	}
}

func TestAPatternThatWouldMisbehaveIsRefused(t *testing.T) {
	long := "/" + strings.Repeat("a", 300)
	many := make([]string, 257)
	for i := range many {
		many[i] = "/x"
	}
	for name, c := range map[string]VMMConfig{
		"a relative path":              {Paths: []string{"etc/shadow"}},
		"an empty path":                {Paths: []string{"  "}},
		"the root, which is all":       {Paths: []string{"/"}},
		"the root spelled another way": {Paths: []string{"/a/.."}},
		"a wildcard inside a name":     {Paths: []string{"/proc/1*/mem"}},
		"a glob that is not ours":      {Paths: []string{"/etc/**"}},
		"a path that is too long":      {Paths: []string{long}},
		"too many paths":               {Paths: many},
		"too many ignores":             {Ignore: many},
		"a relative ignore":            {Ignore: []string{"root/x"}},
		"a syscall nobody has":         {Syscalls: []string{"fork"}},
		"a severity nobody has":        {Severity: "urgent"},
	} {
		c := c
		if _, err := compileVMM(&c); err == nil || !strings.Contains(err.Error(), "vmm:") {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
}

func TestOnlyTheNamedCallsAreReportedAndTheNamesAreForgiving(t *testing.T) {
	all := DefaultVMMRules()
	for _, n := range VMMSyscalls {
		if !all.WatchesSyscall(n) {
			t.Errorf("%s is not watched by default", n)
		}
	}
	if all.WatchesSyscall("fork") || all.WatchesSyscall("openat") || all.WatchesSyscall("flood") {
		t.Error("a call that is not one of the tripwires")
	}
	r, err := compileVMM(&VMMConfig{Syscalls: []string{" PTrace ", "mount"}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.WatchesSyscall("ptrace") || !r.WatchesSyscall("mount") || r.WatchesSyscall("unshare") || r.WatchesSyscall("setns") {
		t.Fatal("only the two")
	}
}

func TestSeveritiesAreCriticalForWhatLoadsCodeOrReadsMemoryAndHighForNamespaces(t *testing.T) {
	r := DefaultVMMRules()
	for n, want := range map[string]string{"ptrace": "critical", "process_vm_writev": "critical", "init_module": "critical", "finit_module": "critical", "kexec_load": "critical", "kexec_file_load": "critical", "process_vm_readv": "high", "mount": "high", "unshare": "high", "setns": "high", "something new": "high"} {
		if got := r.SyscallSeverity(n); got != want {
			t.Errorf("%s: %s, want %s", n, got, want)
		}
	}
	if r.OpenSeverity() != "critical" {
		t.Fatal("a sensitive open is critical")
	}
	lo, _ := compileVMM(&VMMConfig{Severity: "medium"})
	if lo.OpenSeverity() != "medium" {
		t.Fatal("and can be set")
	}
	var nilRules *VMMRules
	if nilRules.OpenSeverity() != "critical" || nilRules.WatchesSyscall("ptrace") || sensitive(nilRules, "/etc/shadow") != "" {
		t.Fatal("no rules means nothing is reported, and never a panic")
	}
}

func TestEveryConfigHasTheTripwireDefaultsAndAFileMayChangeThem(t *testing.T) {
	if DefaultConfig().VMM == nil || sensitive(DefaultConfig().VMM, "/etc/shadow") == "" {
		t.Fatal("no config, no rules: still the defaults")
	}
	c, err := Parse([]byte("suppress: 1m\n"))
	if err != nil || sensitive(c.VMM, "/etc/shadow") == "" {
		t.Fatalf("a file with no vmm section has the defaults: %v", err)
	}
	c, err = Parse([]byte("vmm:\n  paths: [/srv/secret]\n  ignore: [/root/images]\n  syscalls: [ptrace]\n  severity: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sensitive(c.VMM, "/srv/secret/x") == "" || sensitive(c.VMM, "/etc/shadow") == "" || sensitive(c.VMM, "/root/images/a") != "" || c.VMM.WatchesSyscall("mount") || c.VMM.OpenSeverity() != "high" {
		t.Fatalf("%+v", c.VMM)
	}
	for _, bad := range []string{"vmm:\n  path: [/x]\n", "vmm:\n  paths: [x]\n", "vmm:\n  syscalls: [fork]\n", "vmm: 3\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted: %q", bad)
		}
	}
}
