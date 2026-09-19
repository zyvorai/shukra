// Package agent scans QEMU and correlates discrete events.
// It does not invent counters when BPF is not attached.
package agent

import (
	"net"
	"os"
	"time"

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
	State    *state.State
	ProcRoot string
	Watch    *detect.Watchlist
	Host     string
}

func New(st *state.State, procRoot, watchPath, host string) (*Agent, error) {
	var w *detect.Watchlist
	if watchPath != "" {
		b, err := os.ReadFile(watchPath)
		if err != nil {
			return nil, err
		}
		w, err = detect.ParseYAML(b)
		if err != nil {
			return nil, err
		}
	}
	return &Agent{State: st, ProcRoot: procRoot, Watch: w, Host: host}, nil
}

// Refresh rescans QEMU and reports program attach state. Missing BPF is detached, not fake data.
func (a *Agent) Refresh() {
	vms, err := identity.Scan(a.ProcRoot, a.Host)
	if err != nil {
		return
	}
	a.State.SetVMs(vms)
	var programs []state.Program
	for _, p := range observe.Programs() {
		programs = append(programs, state.Program{Name: p.Name, Status: p.Status, Detail: p.Detail})
	}
	a.State.SetPrograms(programs)
	if c := observe.Sample(); c != nil {
		a.State.SetCounters(c)
	}
	observe.Start(a.Ingest)
}

// Ingest joins one discrete event to a VM and, for TCP, the destination watchlist.
func (a *Agent) Ingest(e event.Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
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
	unexpected := false
	if !found && e.Kind == event.KindExec && !allowedExec(e.Comm) {
		if ppid, ok := parentPID(a.ProcRoot, e.PID); ok {
			for _, vm := range vms {
				if vm.Owns(ppid) {
					joined = vm
					found = true
					unexpected = true
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
	if unexpected {
		det := e
		det.Kind = event.KindDetection
		det.Severity = "high"
		det.Message = "unexpected exec " + e.Comm
		event.Normalize(&det)
		a.State.AddEvent(det)
	}
	if e.Kind == event.KindTCPConnect && a.Watch != nil && e.Dst != "" {
		if rule, ok := a.Watch.Match(net.ParseIP(e.Dst)); ok {
			det := e
			det.Kind = event.KindDetection
			det.Severity = rule.Severity
			det.Message = rule.Name + " destination " + e.Dst
			event.Normalize(&det)
			a.State.AddEvent(det)
		}
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
