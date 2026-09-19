// Package agent scans QEMU and correlates discrete events.
// It does not invent counters when BPF is not attached.
package agent

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/observe"
	"github.com/zyvorai/shukra/internal/state"
	"path/filepath"
	"strconv"
	"strings"
)

// Agent owns the refresh loop. The CLI never calls it.
type Agent struct {
	State      *state.State
	ProcRoot   string
	Host       string
	watchPath  string
	cfg        atomic.Pointer[detect.Config]
	sup        detect.Suppressor
	vendorOnce sync.Once
	// eval is touched only by Refresh, which runs on one goroutine at a time.
	eval detect.Evaluator
}

func New(st *state.State, procRoot, watchPath, host string) (*Agent, error) {
	a := &Agent{State: st, ProcRoot: procRoot, Host: host, watchPath: watchPath}
	a.cfg.Store(detect.DefaultConfig())
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// Reload re-reads the detection file. On error the previous rules stay in force,
// so a typo in the YAML cannot silently turn detection off. With no file
// configured it does nothing. Suppression state survives a reload.
func (a *Agent) Reload() error {
	if a.watchPath == "" {
		return nil
	}
	b, err := os.ReadFile(a.watchPath)
	if err != nil {
		return err
	}
	c, err := detect.Parse(b)
	if err != nil {
		return err
	}
	a.cfg.Store(c)
	return nil
}

// Refresh rescans QEMU and reports program attach state. Missing BPF is detached, not fake data.
func (a *Agent) Refresh() {
	vms, err := identity.Scan(a.ProcRoot, a.Host)
	if err != nil {
		return
	}
	a.State.SetVMs(vms)
	a.vendorOnce.Do(func() { a.State.SetCPUVendor(cpuVendor(a.ProcRoot)) })
	tgids := make([]uint32, 0, len(vms))
	for _, vm := range vms {
		tgids = append(tgids, uint32(vm.PID))
	}
	observe.SetWatched(tgids)
	var programs []state.Program
	for _, p := range observe.Programs() {
		programs = append(programs, state.Program{Name: p.Name, Status: p.Status, Detail: p.Detail})
	}
	a.State.SetPrograms(programs)
	if c := observe.Sample(); c != nil {
		a.State.SetCounters(c)
		a.evaluate(time.Now().UTC(), vms, c)
	}
	observe.Start(a.Ingest)
}

// evaluate runs the threshold rules against the latest counters.
func (a *Agent) evaluate(now time.Time, vms []identity.VM, byPID map[uint32]aggregate.Counters) {
	cfg := a.cfg.Load()
	fired := a.eval.Evaluate(now, aggregate.PerVM(vms, byPID), cfg.Thresholds)
	for _, f := range fired {
		var joined identity.VM
		for _, vm := range vms {
			if vm.Name == f.VM {
				joined = vm
				break
			}
		}
		a.raise(now, cfg, "threshold|"+f.Rule.Name+"|"+f.VM, event.Event{
			Kind: event.KindDetection, TS: now, TGID: uint32(joined.PID),
			VM:   event.VM{Name: joined.Name, UUID: joined.UUID, Runtime: joined.Runtime},
			Rule: f.Rule.Name, Severity: f.Rule.Severity, Message: f.Message(),
		})
	}
}

// raise stores a detection unless the same one fired inside the suppression
// window. key says what "the same" means. A held-back repeat is counted, and the
// next one that goes through says how many it stood in for.
func (a *Agent) raise(now time.Time, cfg *detect.Config, key string, det event.Event) {
	ok, held := a.sup.Allow(key, now, cfg.Suppress)
	if !ok {
		a.State.AddSuppressed(1)
		return
	}
	if held > 0 {
		det.Message += fmt.Sprintf(" (%d similar suppressed)", held)
	}
	event.Normalize(&det)
	a.State.AddEvent(det)
}

// Ingest joins one discrete event to a VM and applies the detection rules.
func (a *Agent) Ingest(e event.Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	cfg := a.cfg.Load()
	tgid := e.TGID
	if tgid == 0 {
		tgid = e.PID
	}
	vms := a.State.VMs()
	var joined identity.VM
	var found bool
	for _, vm := range vms {
		if vm.Owns(tgid) || vm.Owns(e.PID) {
			joined = vm
			found = true
			break
		}
	}
	// exec and exit carry the parent's tgid from the kernel, which is still right
	// after the process has gone. /proc is only the fallback for an exec without one.
	unexpected := false
	if !found && (e.Kind == event.KindExec || e.Kind == event.KindExit) {
		expected := e.Kind != event.KindExec || allowedExec(e.Comm) || cfg.AllowsExec(e.Comm)
		ppid := e.PPID
		if ppid == 0 && !expected {
			ppid, _ = parentPID(a.ProcRoot, e.PID)
		}
		if ppid != 0 {
			for _, vm := range vms {
				if vm.Owns(ppid) {
					joined = vm
					found = true
					unexpected = !expected
					break
				}
			}
		}
	}
	if found {
		e.VM = event.VM{Name: joined.Name, UUID: joined.UUID, Runtime: joined.Runtime}
		e.TGID = uint32(joined.PID)
	}
	event.Normalize(&e)
	a.State.AddEvent(e)

	detection := func(rule, severity, msg string) event.Event {
		det := e
		det.Kind = event.KindDetection
		det.Rule, det.Severity, det.Message = rule, severity, msg
		return det
	}
	if unexpected {
		a.raise(e.TS, cfg, "exec|"+e.VM.Name+"|"+e.Comm,
			detection("unexpected-exec", "high", "unexpected exec "+e.Comm))
	}
	if e.Kind != event.KindTCPConnect {
		return
	}
	if e.Dst != "" {
		if rule, ok := cfg.Watch.Match(net.ParseIP(e.Dst)); ok {
			a.raise(e.TS, cfg, "dest|"+rule.Name+"|"+e.VM.Name+"|"+e.Dst,
				detection(rule.Name, rule.Severity, rule.Name+" destination "+e.Dst))
		}
	}
	if rule, ok := cfg.MatchPort(e.DPort); ok {
		a.raise(e.TS, cfg, fmt.Sprintf("port|%s|%s|%s:%d", rule.Name, e.VM.Name, e.Dst, e.DPort),
			detection(rule.Name, rule.Severity, fmt.Sprintf("%s port %d to %s", rule.Name, e.DPort, e.Dst)))
	}
}

func allowedExec(comm string) bool {
	c := strings.ToLower(strings.TrimSpace(comm))
	if c == "" {
		return false
	}
	if strings.HasPrefix(c, "qemu-system") || strings.HasPrefix(c, "cpu") || strings.HasPrefix(c, "io") {
		return true
	}
	return strings.Contains(c, "vhost") || strings.Contains(c, "kvm")
}

func parentPID(root string, pid uint32) (uint32, bool) {
	if pid == 0 || root == "" {
		return 0, false
	}
	b, err := os.ReadFile(filepath.Join(root, strconv.FormatUint(uint64(pid), 10), "status"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		n, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || n == 0 {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}

// cpuVendor is the first vendor_id in <proc>/cpuinfo. It is empty on a CPU that
// has none (arm64) or when the file cannot be read.
func cpuVendor(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "cpuinfo"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "vendor_id" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
