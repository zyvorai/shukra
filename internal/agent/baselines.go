package agent

import (
	"fmt"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
)

// SetBaselines gives the agent the store learned baselines live in. Nothing is learned, and nothing is reported,
// unless the rules file has a baselines section: a store on its own does nothing.
//
// persisted says whether what is learned is kept across a restart: without it, learning starts over each time
// the daemon does, and a daemon that restarts more often than the learning period never reports anything.
func (a *Agent) SetBaselines(s *baseline.Store, persisted bool) {
	a.base = s
	a.basePersisted = persisted
	if s != nil {
		if bc := a.cfg.Load().Baselines; bc != nil {
			s.SetOptions(bc.Options())
		}
		a.State.SetBaselines(baselineView{a})
	}
}

// baselineView is the state's window onto the agent's baselines.
type baselineView struct{ a *Agent }

func (v baselineView) Enabled() bool             { return v.a.cfg.Load().Baselines != nil }
func (v baselineView) Persisted() bool           { return v.a.basePersisted }
func (v baselineView) Options() baseline.Options { return v.a.base.Options() }
func (v baselineView) Forget(vm string) bool     { return v.a.base.Forget(vm) }
func (v baselineView) Items(vm string, limit int) []baseline.Learned {
	return v.a.base.Items(vm, limit)
}
func (v baselineView) Status(vm string, now time.Time) []baseline.VMStatus {
	return v.a.base.Status(vm, now)
}

// baselineItem is the thing an event teaches about its VM: a network it talked to, a site it looked up, or a
// network that connected in. It is empty for an event that teaches nothing, such as a name that was cut short
// (only part of it is known, so it is not a site).
func baselineItem(e event.Event) (baseline.Kind, string) {
	switch e.Kind {
	case event.KindGuestConnect, event.KindGuestFlow:
		return baseline.Destination, baseline.Prefix(e.Dst)
	case event.KindGuestInbound:
		return baseline.InboundPeer, baseline.Prefix(e.Src)
	case event.KindGuestDNS:
		if e.DNSTruncated {
			return "", ""
		}
		return baseline.DNSSuffix, baseline.Registrable(e.DNSName)
	}
	return "", ""
}

// observeBaseline learns from a guest event that has been joined to its VM, and reports what is new.
func (a *Agent) observeBaseline(e event.Event, cfg *detect.Config) {
	bc := cfg.Baselines
	if bc == nil || a.base == nil || e.VM.Name == "" {
		return
	}
	kind, item := baselineItem(e)
	if item == "" || !bc.Learns(kind) {
		return
	}
	res := a.base.Observe(e.VM.Name, kind, item, e.TS)
	detection := func(rule, severity, msg string) event.Event {
		det := e
		det.Kind = event.KindDetection
		det.Rule, det.Severity, det.Message = rule, severity, msg
		return det
	}
	if res.Verdict == baseline.New {
		a.raise(e.TS, cfg, fmt.Sprintf("baseline|%s|%s|%s", kind, e.VM.Name, item),
			detection("new-"+string(kind), bc.SeverityOf(kind), newItemMessage(e, kind, item)))
	}
	if res.CapReached {
		a.raise(e.TS, cfg, "baseline-cap|"+e.VM.Name,
			detection("baseline-cap", "low", fmt.Sprintf("%s has used its %d new-item alerts for the day: further new items are learned but not reported until tomorrow (shukractl baseline %s shows them)",
				e.VM.Name, bc.MaxAlertsPerDay, e.VM.Name)))
	}
}

func newItemMessage(e event.Event, kind baseline.Kind, item string) string {
	switch kind {
	case baseline.DNSSuffix:
		return fmt.Sprintf("%s looked up %s for the first time (%s, %s)", e.VM.Name, item, e.DNSName, e.QType)
	case baseline.InboundPeer:
		return fmt.Sprintf("%s was connected to from %s for the first time (%s, to port %d)", e.VM.Name, item, e.Src, e.DPort)
	}
	proto := e.Proto
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s contacted %s for the first time (%s to %s:%d)", e.VM.Name, item, proto, e.Dst, e.DPort)
}
