// Package recorder is the per-VM flight recorder: a bounded ring, replayed by time window.
package recorder

import (
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

const DefaultCap = 4096

// Recorder keeps the newest events per VM. The host rollup key is "_host".
type Recorder struct {
	mu  sync.Mutex
	cap int
	buf map[string][]event.Event
}

func New(cap int) *Recorder {
	if cap <= 0 {
		cap = DefaultCap
	}
	return &Recorder{cap: cap, buf: map[string][]event.Event{}}
}

func keyOf(e event.Event) string {
	if e.VM.Name == "" {
		return "_host"
	}
	return e.VM.Name
}

// Add copies e onto the ring for its VM, dropping the oldest event past cap.
func (r *Recorder) Add(e event.Event) {
	event.Normalize(&e)
	r.mu.Lock()
	defer r.mu.Unlock()
	k := keyOf(e)
	r.buf[k] = append(r.buf[k], e)
	if len(r.buf[k]) > r.cap {
		r.buf[k] = append([]event.Event(nil), r.buf[k][len(r.buf[k])-r.cap:]...)
	}
}

// Window returns events for vm whose timestamp is within d of now, oldest first.
// vm "_" or "" returns every VM, still filtered by time.
func (r *Recorder) Window(vm string, d time.Duration, now time.Time) []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-d)
	var out []event.Event
	if vm == "" || vm == "_" {
		for _, evs := range r.buf {
			out = append(out, filter(evs, cutoff)...)
		}
		return out
	}
	return filter(r.buf[vm], cutoff)
}

func filter(evs []event.Event, cutoff time.Time) []event.Event {
	var out []event.Event
	for _, e := range evs {
		if !e.TS.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

// Snapshot copies every held event, grouped by VM (sorted by name) and oldest
// first within a VM. Feeding it back through Add restores the same rings.
func (r *Recorder) Snapshot() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]string, 0, len(r.buf))
	for k := range r.buf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []event.Event
	for _, k := range keys {
		out = append(out, r.buf[k]...)
	}
	return out
}
