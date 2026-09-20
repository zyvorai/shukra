package detect

import (
	"fmt"
	"path"
	"strings"
)

// The VMM tripwires report files a VMM process (QEMU, or anything it started) opens and calls it has no business
// making. What counts as sensitive is decided here, in userspace, so it can change with the rules file and not
// with the kernel program.

// DefaultVMMPaths are the files and directories that a VMM has no reason to open, and an attacker who has got
// into one would. A pattern matches the path itself and everything under it, and * stands for exactly one path
// segment (/proc/*/mem is any process's memory, and /proc/self/mem too).
var DefaultVMMPaths = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d",
	"/etc/ssh", "/root/.ssh", "/home/*/.ssh",
	"/proc/*/mem", "/proc/*/task/*/mem", "/proc/kcore", "/proc/kmem", "/proc/sysrq-trigger",
	"/var/run/docker.sock", "/run/docker.sock", "/run/containerd", "/var/run/containerd",
	"/etc/shukra", "/var/lib/shukra",
	"/etc/kubernetes", "/var/lib/rancher/k3s/server", "/etc/rancher",
}

// VMMSyscalls are the calls the tripwire can report other than opens, by the name the rules file uses. All of
// them are reported unless the file says otherwise.
var VMMSyscalls = []string{"ptrace", "process_vm_writev", "process_vm_readv", "mount", "unshare", "setns", "init_module", "finit_module", "kexec_load", "kexec_file_load"}

// vmmSeverity is how serious a call is by default: reading another process's memory or loading code into the
// kernel is critical, and changing the namespaces or mounts is high.
var vmmSeverity = map[string]string{
	"ptrace": "critical", "process_vm_writev": "critical", "init_module": "critical", "finit_module": "critical",
	"kexec_load": "critical", "kexec_file_load": "critical",
	"process_vm_readv": "high", "mount": "high", "unshare": "high", "setns": "high",
}

// VMMConfig is the vmm: section of the rules file. Everything in it is optional: with no section the defaults
// apply, and a section that names some of it leaves the rest as it was.
type VMMConfig struct {
	// Paths are files and directories to add to the defaults. * stands for one path segment.
	Paths []string `yaml:"paths"`
	// Ignore are paths that are never reported as sensitive, for a disk image kept under a directory that the
	// defaults or Paths name. It wins over both.
	Ignore []string `yaml:"ignore"`
	// Syscalls limits which of VMMSyscalls are reported. Empty means all of them.
	Syscalls []string `yaml:"syscalls"`
	// Defaults, when false, drops the built-in paths, so that only Paths are sensitive. It is true if unset.
	Defaults *bool `yaml:"defaults"`
	// Severity is that of a sensitive open. It is critical if unset.
	Severity string `yaml:"severity"`
}

// pattern is a path pattern split into segments.
type pattern struct {
	raw  string
	segs []string
}

// VMMRules is what the tripwire judges a report by. It is never nil in a Config.
type VMMRules struct {
	paths    []pattern
	ignore   []pattern
	calls    map[string]bool
	severity string
}

func compilePattern(kind, s string) (pattern, error) {
	s = strings.TrimSpace(s)
	if s == "" || !strings.HasPrefix(s, "/") {
		return pattern{}, fmt.Errorf("vmm: %s %q must be an absolute path, starting with /", kind, s)
	}
	if len(s) > 256 {
		return pattern{}, fmt.Errorf("vmm: %s %q is longer than 256 bytes", kind, s[:40]+"...")
	}
	p := path.Clean(s)
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if p == "/" {
		return pattern{}, fmt.Errorf("vmm: %s %q would match every file", kind, s)
	}
	for _, seg := range segs {
		if strings.Contains(seg, "*") && seg != "*" {
			return pattern{}, fmt.Errorf("vmm: %s %q: * must be a whole path segment (/proc/*/mem), not part of a name", kind, s)
		}
	}
	return pattern{raw: p, segs: segs}, nil
}

// matches says the path is the pattern or is under it, on a segment boundary: /etc/ssh matches /etc/ssh and
// /etc/ssh/sshd_config, and not /etc/ssh2.
func (p pattern) matches(segs []string) bool {
	if len(segs) < len(p.segs) {
		return false
	}
	for i, want := range p.segs {
		if want != "*" && want != segs[i] {
			return false
		}
	}
	return true
}

// DefaultVMMRules is what runs when the rules file has no vmm: section.
func DefaultVMMRules() *VMMRules {
	r, _ := compileVMM(nil)
	return r
}

func compileVMM(c *VMMConfig) (*VMMRules, error) {
	if c == nil {
		c = &VMMConfig{}
	}
	const maxPatterns = 256
	if len(c.Paths) > maxPatterns || len(c.Ignore) > maxPatterns {
		return nil, fmt.Errorf("vmm: at most %d paths and %d ignore entries", maxPatterns, maxPatterns)
	}
	r := &VMMRules{calls: map[string]bool{}, severity: "critical"}
	var paths []string
	if c.Defaults == nil || *c.Defaults {
		paths = append(paths, DefaultVMMPaths...)
	}
	for _, s := range paths {
		p, err := compilePattern("path", s)
		if err != nil {
			return nil, err
		}
		r.paths = append(r.paths, p)
	}
	for _, s := range c.Paths {
		p, err := compilePattern("path", s)
		if err != nil {
			return nil, err
		}
		r.paths = append(r.paths, p)
	}
	for _, s := range c.Ignore {
		p, err := compilePattern("ignore", s)
		if err != nil {
			return nil, err
		}
		r.ignore = append(r.ignore, p)
	}
	known := map[string]bool{}
	for _, n := range VMMSyscalls {
		known[n] = true
	}
	if len(c.Syscalls) == 0 {
		for _, n := range VMMSyscalls {
			r.calls[n] = true
		}
	}
	for _, n := range c.Syscalls {
		n = strings.TrimSpace(strings.ToLower(n))
		if !known[n] {
			return nil, fmt.Errorf("vmm: syscall %q is not one of %s", n, strings.Join(VMMSyscalls, ", "))
		}
		r.calls[n] = true
	}
	if c.Severity != "" {
		if !severities[c.Severity] {
			return nil, fmt.Errorf("vmm: severity %q is not low, medium, high or critical", c.Severity)
		}
		r.severity = c.Severity
	}
	return r, nil
}

// SensitivePath says whether a path a VMM opened is one to report, and which pattern it matched. The path is
// cleaned first (.. and repeated slashes are resolved), so /etc/../etc//shadow is /etc/shadow. A path that is
// not absolute cannot be judged and is not reported here: it is shown on the event as it was given.
func (r *VMMRules) SensitivePath(p string) (matched string, ok bool) {
	if r == nil || !strings.HasPrefix(p, "/") {
		return "", false
	}
	segs := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	for _, ig := range r.ignore {
		if ig.matches(segs) {
			return "", false
		}
	}
	for _, pat := range r.paths {
		if pat.matches(segs) {
			return pat.raw, true
		}
	}
	return "", false
}

// WatchesSyscall says whether a call is one the rules report.
func (r *VMMRules) WatchesSyscall(name string) bool { return r != nil && r.calls[name] }

// OpenSeverity is the severity of a sensitive open.
func (r *VMMRules) OpenSeverity() string {
	if r == nil {
		return "critical"
	}
	return r.severity
}

// SyscallSeverity is the severity of a call: critical for one that reads another process's memory, loads code
// into the kernel or replaces it, and high for a change of mounts or namespaces.
func (r *VMMRules) SyscallSeverity(name string) string {
	if s, ok := vmmSeverity[name]; ok {
		return s
	}
	return "high"
}
