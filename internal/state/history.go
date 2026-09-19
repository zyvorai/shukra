package state

import (
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

// The counters are cumulative since the daemon attached. A slow disk an hour ago
// would keep a lifetime p99 high for good, so Explain compares against a snapshot
// from one window ago instead. Snapshots hold only the threads of the VMs, and are
// taken at most every snapEvery.
const (
	snapEvery = 10 * time.Second
	snapKeep  = 6 * time.Minute
	// DefaultExplainWindow is how far back Explain looks unless asked otherwise.
	DefaultExplainWindow = 60 * time.Second
	// MaxExplainWindow is the longest window that history is kept for.
	MaxExplainWindow = 5 * time.Minute
	// minSpan is the least history a windowed verdict will stand on. Less than
	// this is a few scans, and one busy second would look like the whole story.
	minSpan = 20 * time.Second
)

type snapshot struct {
	at      time.Time
	threads map[string]map[uint32]aggregate.Counters // VM name -> tid -> counters
	drops   map[string]dropSnap                      // tap name -> what the kernel dropped on it, when the drops program was measuring
}

func (s *State) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// recordLocked takes a snapshot if the last one is old enough. Caller holds s.mu.
func (s *State) recordLocked(now time.Time) {
	if n := len(s.history); n > 0 && now.Sub(s.history[n-1].at) < snapEvery {
		return
	}
	snap := snapshot{at: now, threads: map[string]map[uint32]aggregate.Counters{}}
	for _, vm := range s.vms {
		m := map[uint32]aggregate.Counters{}
		for _, tid := range vm.Threads {
			if c, ok := s.byPID[uint32(tid)]; ok {
				m[uint32(tid)] = c.Clone()
			}
		}
		snap.threads[vm.Name] = m
	}
	if s.dropSource != nil && s.programAttachedLocked("drops") {
		var taps []TapStat
		if s.tapSource != nil {
			taps = s.tapSource()
		}
		snap.drops = snapsFrom(taps, s.dropSource())
	}
	s.history = append(s.history, snap)
	cut := 0
	for cut < len(s.history)-1 && now.Sub(s.history[cut].at) > snapKeep {
		cut++
	}
	s.history = append([]snapshot(nil), s.history[cut:]...)
}

// windowedInputs returns, for one VM, the counters that accumulated over roughly
// the last window, per thread, and the span they really cover. ok is false when
// there is not enough history yet, and the caller falls back to lifetime.
func (s *State) windowedInputs(vm identity.VM, now time.Time, window time.Duration) (map[uint32]aggregate.Counters, time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if window <= 0 || len(s.history) == 0 {
		return nil, 0, false
	}
	base, span, ok := s.baseLocked(now, window)
	if !ok {
		return nil, 0, false
	}
	old := base.threads[vm.Name]
	out := make(map[uint32]aggregate.Counters, len(vm.Threads))
	for _, tid := range vm.Threads {
		cur, ok := s.byPID[uint32(tid)]
		if !ok {
			continue
		}
		out[uint32(tid)] = aggregate.Delta(cur, old[uint32(tid)]) // a thread new in the window has no base: all of it is the window's
	}
	return out, span, true
}

// baseLocked picks the snapshot a window is measured from: the newest one at least a window old, or
// the oldest when the history is younger than the window, and only when it spans enough time to mean
// something. Caller holds s.mu.
func (s *State) baseLocked(now time.Time, window time.Duration) (*snapshot, time.Duration, bool) {
	if window <= 0 || len(s.history) == 0 {
		return nil, 0, false
	}
	window = min(window, MaxExplainWindow)
	var base *snapshot
	cut := now.Add(-window)
	for i := len(s.history) - 1; i >= 0; i-- {
		if !s.history[i].at.After(cut) {
			base = &s.history[i]
			break
		}
	}
	if base == nil { // younger than the window: use the oldest, if it is old enough to mean something
		base = &s.history[0]
	}
	span := now.Sub(base.at)
	if span < minSpan {
		return nil, 0, false
	}
	return base, span, true
}

// dropBase is the drop counts a window is measured from. It says false when there is no snapshot
// with drop counts old enough, and the caller reads the whole lifetime instead.
func (s *State) dropBase(now time.Time, window time.Duration) (map[string]dropSnap, time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	base, span, ok := s.baseLocked(now, window)
	if !ok || base.drops == nil {
		return nil, 0, false
	}
	return base.drops, span, true
}

func (s *State) programAttachedLocked(name string) bool {
	for _, p := range s.programs {
		if p.Name == name {
			return p.Status == "attached"
		}
	}
	return false
}
