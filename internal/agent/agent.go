// Package agent scans QEMU and correlates discrete events.
// It does not invent counters when BPF is not attached.
package agent

import (
	"fmt"
	"log"
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
	// vms is what the last scans found, keyed by pid: a restarted VM has a new pid,
	// so it reads as a stop and a start. Touched only by Refresh.
	vms       map[int]*trackedVM
	firstScan bool
	// eval is touched only by Refresh, which runs on one goroutine at a time.
	eval detect.Evaluator
}

func New(st *state.State, procRoot, watchPath, host string) (*Agent, error) {
	a := &Agent{State: st, ProcRoot: procRoot, Host: host, watchPath: watchPath, vms: map[int]*trackedVM{}, firstScan: true}
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
	err := a.reload()
	a.State.SetRulesStatus(err)
	return err
}

func (a *Agent) reload() error {
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
	a.trackVMs(time.Now().UTC(), vms)
	a.vendorOnce.Do(func() { a.State.SetCPUVendor(cpuVendor(a.ProcRoot)) })
	tgids := make([]uint32, 0, len(vms))
	for _, vm := range vms {
		tgids = append(tgids, uint32(vm.PID))
	}
	observe.SetWatched(tgids)
	var taps []string
	for _, vm := range vms {
		taps = append(taps, vm.Taps...)
	}
	observe.SyncTaps(taps)
	if acted := a.State.ReapplyIsolations(); len(acted) > 0 {
		log.Printf("isolation re-applied for %s", strings.Join(acted, ", "))
	}
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
	observe.StartTap(a.Ingest)
}

// evaluate runs the threshold rules against the latest counters.
func (a *Agent) evaluate(now time.Time, vms []identity.VM, byPID map[uint32]aggregate.Counters) {
	cfg := a.cfg.Load()
	a.eval.SetForeignDrops(a.State.ForeignDrops())
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
	if e.Kind == event.KindGuestConnect || e.Kind == event.KindGuestFlow {
		a.ingestGuest(e, cfg)
		return
	}
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
	a.connectRules(e, cfg, detection)
}

// The suppression key includes the attribution: QEMU's own connect and the guest's are
// different facts, and one must not hide the other.
// connectRules applies the destination and port rules to one connect, wherever it
// was seen. The detection keeps the event's attribution, so a rule that fires on
// what the guest did says the guest did it.
func (a *Agent) connectRules(e event.Event, cfg *detect.Config, detection func(rule, severity, msg string) event.Event) {
	proto := e.Proto
	if proto == "" {
		proto = "tcp" // a host connect is always TCP
	}
	if e.Dst != "" {
		if rule, ok := cfg.Watch.Match(net.ParseIP(e.Dst)); ok {
			// TCP and UDP to the same address are different facts, so an alert for one
			// does not hide the other.
			a.raise(e.TS, cfg, "dest|"+rule.Name+"|"+e.VM.Name+"|"+e.Attribution+"|"+proto+"|"+e.Dst,
				detection(rule.Name, rule.Severity, rule.Name+" destination "+e.Dst))
		}
	}
	if rule, ok := cfg.MatchPort(e.DPort, proto); ok {
		note := ""
		if proto != "tcp" {
			note = " (" + proto + ")"
		}
		a.raise(e.TS, cfg, fmt.Sprintf("port|%s|%s|%s|%s|%s:%d", rule.Name, e.VM.Name, e.Attribution, proto, e.Dst, e.DPort),
			detection(rule.Name, rule.Severity, fmt.Sprintf("%s port %d%s to %s", rule.Name, e.DPort, note, e.Dst)))
	}
}

// ingestGuest handles a connect the guest made, seen on its tap. It joins the
// event to the VM that owns the tap and marks it guest-attributed. A tap that no
// VM in the current scan owns stays unattributed: this never names a guess.
func (a *Agent) ingestGuest(e event.Event, cfg *detect.Config) {
	for _, vm := range a.State.VMs() {
		for _, t := range vm.Taps {
			if t == e.Iface {
				e.VM = event.VM{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime}
				e.TGID = uint32(vm.PID)
				e.Attribution = event.AttributionGuestTap
			}
		}
	}
	event.Normalize(&e)
	a.State.AddEvent(e)
	if e.VM.Name == "" {
		return
	}
	a.connectRules(e, cfg, func(rule, severity, msg string) event.Event {
		det := e
		det.Kind = event.KindDetection
		det.Rule, det.Severity, det.Message = rule, severity, msg
		return det
	})
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

type trackedVM struct {
	vm     identity.VM
	misses int
}

// stopAfterMisses is how many scans in a row must not find a VM before it is
// reported stopped. Scan skips a process whose /proc files fail to read for a
// moment, and one bad read must not look like a VM stopping and starting again.
const stopAfterMisses = 2

// trackVMs turns changes in the VM set into events. The first scan is silent:
// VMs already running when the daemon starts were not started by anyone just now.
func (a *Agent) trackVMs(now time.Time, vms []identity.VM) {
	seen := make(map[int]bool, len(vms))
	for _, vm := range vms {
		seen[vm.PID] = true
		if t, ok := a.vms[vm.PID]; ok {
			t.vm, t.misses = vm, 0
			continue
		}
		a.vms[vm.PID] = &trackedVM{vm: vm}
		if !a.firstScan {
			a.vmEvent(now, event.KindVMStart, vm, fmt.Sprintf("VM %s appeared (pid %d)", vm.Name, vm.PID))
		}
	}
	for pid, t := range a.vms {
		if seen[pid] {
			continue
		}
		if t.misses++; t.misses >= stopAfterMisses {
			a.vmEvent(now, event.KindVMStop, t.vm, fmt.Sprintf("VM %s is gone (pid %d)", t.vm.Name, pid))
			delete(a.vms, pid)
		}
	}
	a.firstScan = false
}

func (a *Agent) vmEvent(now time.Time, kind event.Kind, vm identity.VM, msg string) {
	e := event.Event{
		Kind: kind, TS: now, PID: uint32(vm.PID), TGID: uint32(vm.PID), Comm: vm.Comm,
		VM:      event.VM{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime},
		Message: msg,
	}
	event.Normalize(&e)
	a.State.AddEvent(e)
}
