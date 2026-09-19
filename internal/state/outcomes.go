package state

import (
	"fmt"
	"time"
)

// A VM's connections are said to be failing when at least this many finished in the window and at least
// half of them were refused or never answered. A handful of refusals is normal; a run of them is not.
const (
	connectFloor     = 10
	connectFailRatio = 0.5
)

func subOutcomes(cur, old Outcomes) Outcomes {
	return Outcomes{
		OutSyn: subOrAll(cur.OutSyn, old.OutSyn), OutOK: subOrAll(cur.OutOK, old.OutOK), OutRefused: subOrAll(cur.OutRefused, old.OutRefused),
		OutTimeout: subOrAll(cur.OutTimeout, old.OutTimeout), OutRetrans: subOrAll(cur.OutRetrans, old.OutRetrans), OutBlocked: subOrAll(cur.OutBlocked, old.OutBlocked),
		InSyn: subOrAll(cur.InSyn, old.InSyn), InOK: subOrAll(cur.InOK, old.InOK), InRefused: subOrAll(cur.InRefused, old.InRefused),
		InIgnored: subOrAll(cur.InIgnored, old.InIgnored), InRetrans: subOrAll(cur.InRetrans, old.InRetrans), InBlocked: subOrAll(cur.InBlocked, old.InBlocked),
	}
}

func addOutcomes(a, b Outcomes) Outcomes {
	return Outcomes{
		OutSyn: a.OutSyn + b.OutSyn, OutOK: a.OutOK + b.OutOK, OutRefused: a.OutRefused + b.OutRefused, OutTimeout: a.OutTimeout + b.OutTimeout,
		OutRetrans: a.OutRetrans + b.OutRetrans, OutBlocked: a.OutBlocked + b.OutBlocked,
		InSyn: a.InSyn + b.InSyn, InOK: a.InOK + b.InOK, InRefused: a.InRefused + b.InRefused, InIgnored: a.InIgnored + b.InIgnored,
		InRetrans: a.InRetrans + b.InRetrans, InBlocked: a.InBlocked + b.InBlocked,
	}
}

// outcomesBase is the per-tap outcome counts a window is measured from, and says false when there is no
// snapshot old enough that carried any.
func (s *State) outcomesBase(now time.Time, window time.Duration) (map[string]Outcomes, time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	base, span, ok := s.baseLocked(now, window)
	if !ok || base.outcomes == nil {
		return nil, 0, false
	}
	return base.outcomes, span, true
}

// OutcomesOver is, per VM, what became of its TCP handshakes over roughly the last window, or over the
// daemon's lifetime when there is not enough history yet; over says which. Nothing while the tap program
// is not attached: there is no zero to report for something not measured.
func (s *State) OutcomesOver(vm string, now time.Time, window time.Duration) (map[string]Outcomes, string) {
	if !s.tapAttached() {
		return nil, ""
	}
	rows := s.Taps(vm)
	if rows == nil {
		return nil, ""
	}
	base, span, ok := s.outcomesBase(now, window)
	over := "lifetime"
	if ok {
		over = span.Round(time.Second).String()
	}
	out := map[string]Outcomes{}
	for _, r := range rows {
		o := r.Outcomes
		if ok {
			o = subOutcomes(o, base[r.Tap])
		}
		out[r.VM] = addOutcomes(out[r.VM], o)
	}
	return out, over
}

// connectFailing says whether most of a VM's finished connections failed, and describes it.
func connectFailing(o Outcomes) (bool, string) {
	failed := o.OutRefused + o.OutTimeout
	finished := o.OutOK + failed
	if finished < connectFloor || float64(failed) < connectFailRatio*float64(finished) {
		return false, ""
	}
	return true, fmt.Sprintf("%d of %d finished connections failed: %d refused, %d never answered", failed, finished, o.OutRefused, o.OutTimeout)
}
