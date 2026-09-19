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
	for _, vm := range a.State.VMs() {
		if vm.Owns(tgid) || vm.Owns(e.PID) {
			e.VM = event.VM{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime}
			e.TGID = uint32(vm.PID)
			break
		}
	}
	event.Normalize(&e)
	a.State.AddEvent(e)
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
