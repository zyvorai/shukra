package state

import (
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
)

// BaselineView is what the state needs to know about learned baselines. The agent implements it: whether the
// rules file has them on is the agent's to say, and the store is where they live.
type BaselineView interface {
	// Enabled says whether the rules file turns baselines on.
	Enabled() bool
	// Persisted says whether what is learned survives a restart (a data directory is configured).
	Persisted() bool
	Options() baseline.Options
	Status(vm string, now time.Time) []baseline.VMStatus
	Items(vm string, limit int) []baseline.Learned
	Forget(vm string) bool
}

// SetBaselines gives the state its view of learned baselines.
func (s *State) SetBaselines(v BaselineView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baselines = v
}

// Baselines is the view, or nil when this build or run has none.
func (s *State) Baselines() BaselineView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.baselines
}
