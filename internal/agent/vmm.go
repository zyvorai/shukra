package agent

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
)

// ingestVMM joins a VMM tripwire event to the VM whose VMM it came from, records it, and applies the tripwire
// rules. The kernel names the VMM process it descends from, so a shell a VMM started and the program the shell
// ran are the VM's too, though they are not among its threads.
func (a *Agent) ingestVMM(e event.Event, cfg *detect.Config) {
	for _, vm := range a.State.VMs() {
		if vm.Owns(e.TGID) {
			e.VM = event.VM{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime}
			e.TGID = uint32(vm.PID)
			break
		}
	}
	if e.Kind == event.KindVMMOpen {
		a.resolveRelative(&e)
	}
	event.Normalize(&e)
	a.State.AddEvent(e)
	if e.VM.Name == "" {
		return // a VMM the scan no longer knows: there is no VM to say it about
	}
	a.vmmRules(e, cfg)
}

// resolveRelative makes a relative path absolute when it can: the process's working directory, or the directory
// its descriptor names, is read from /proc while the process is there. A short-lived process may be gone by the
// time the event arrives, and then the path stays as it was given, which cannot be judged. The event says how
// it was resolved.
func (a *Agent) resolveRelative(e *event.Event) {
	if e.Path == "" || strings.HasPrefix(e.Path, "/") || e.PID == 0 {
		return
	}
	link := filepath.Join(a.ProcRoot, strconv.FormatUint(uint64(e.PID), 10), "cwd")
	from := "the process's working directory"
	if strings.HasPrefix(e.Detail, "relative to fd ") {
		// Relative to a descriptor, so the working directory is not the base, whatever becomes of the descriptor.
		fd, ok := descriptorOf(e.Detail)
		if !ok {
			return
		}
		link = filepath.Join(a.ProcRoot, strconv.FormatUint(uint64(e.PID), 10), "fd", strconv.Itoa(fd))
		from = fmt.Sprintf("fd %d", fd)
	}
	base, err := os.Readlink(link)
	if err != nil || !path.IsAbs(base) {
		return
	}
	e.Detail = fmt.Sprintf("opened as %q, resolved from %s (%s)", e.Path, from, base)
	e.Path = path.Join(base, e.Path)
}

// descriptorOf reads the descriptor out of the "relative to fd N" that the decoder puts on such an open.
func descriptorOf(detail string) (int, bool) {
	rest, ok := strings.CutPrefix(detail, "relative to fd ")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil && n >= 0
}

// vmmRules raises a detection for what the tripwire is for: a VMM process tree opening a sensitive file,
// making a call a VMM has no business making, or making so many that the tripwire cannot report them all. Each
// is held back per VM, what it touched and who touched it, so a shell that reads a file twice is one detection.
func (a *Agent) vmmRules(e event.Event, cfg *detect.Config) {
	det := e
	det.Kind = event.KindDetection
	who := fmt.Sprintf("%s (pid %d) in %s's VMM process tree", e.Comm, e.PID, e.VM.Name)
	switch e.Kind {
	case event.KindVMMOpen:
		pat, ok := cfg.VMM.SensitivePath(e.Path)
		if !ok {
			return
		}
		how := "opened"
		if e.Write {
			how = "opened for writing"
		}
		det.Rule, det.Severity = "vmm-sensitive-open", cfg.VMM.OpenSeverity()
		det.Message = fmt.Sprintf("%s %s %s, which matches %s: a VMM has no reason to", who, how, e.Path, pat)
		a.raise(e.TS, cfg, "vmm-open|"+e.VM.Name+"|"+path.Clean(e.Path)+"|"+e.Comm, det)
	case event.KindVMMCall:
		if e.Syscall == "flood" {
			det.Rule, det.Severity = "vmm-flood", "critical"
			det.Message = fmt.Sprintf("%s made %d more file opens and calls in a second than the tripwire reports: a VMM in steady state makes none", who, e.Count)
			a.raise(e.TS, cfg, "vmm-flood|"+e.VM.Name+"|"+e.Comm, det)
			return
		}
		if !cfg.VMM.WatchesSyscall(e.Syscall) {
			return
		}
		det.Rule, det.Severity = "vmm-syscall", cfg.VMM.SyscallSeverity(e.Syscall)
		det.Message = fmt.Sprintf("%s called %s", who, e.Syscall)
		if e.Detail != "" {
			det.Message += " (" + e.Detail + ")"
		}
		det.Message += ": a VMM has no business doing that"
		a.raise(e.TS, cfg, "vmm-call|"+e.VM.Name+"|"+e.Syscall+"|"+e.Comm, det)
	}
}
