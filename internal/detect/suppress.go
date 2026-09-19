package detect

import (
	"sync"
	"time"
)

// maxSuppressKeys bounds memory. Keys include values a guest can influence, such
// as a destination address, so the table cannot be allowed to grow with them.
const maxSuppressKeys = 4096

type suppressed struct {
	until time.Time
	held  uint64
}

// Suppressor holds back repeats of the same detection for a window. The first
// occurrence goes through; repeats inside the window are counted, and the count
// is handed back on the next one that goes through.
type Suppressor struct {
	mu   sync.Mutex
	seen map[string]*suppressed
}

// Allow reports whether a detection with this key should be raised at now. When
// it does, held is how many repeats were held back since the last one. A zero
// window turns suppression off. If the table is full of live keys the detection
// is let through unrecorded: memory stays bounded, and it fails toward alerting.
func (s *Suppressor) Allow(key string, now time.Time, window time.Duration) (ok bool, held uint64) {
	if window <= 0 {
		return true, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]*suppressed{}
	}
	if e, found := s.seen[key]; found {
		if now.Before(e.until) {
			e.held++
			return false, 0
		}
		held = e.held
		e.held = 0
		e.until = now.Add(window)
		return true, held
	}
	if len(s.seen) >= maxSuppressKeys {
		for k, e := range s.seen {
			// An expired entry is safe to drop even with repeats held: the caller
			// has already counted them.
			if !now.Before(e.until) {
				delete(s.seen, k)
			}
		}
		if len(s.seen) >= maxSuppressKeys {
			return true, 0
		}
	}
	s.seen[key] = &suppressed{until: now.Add(window)}
	return true, 0
}
