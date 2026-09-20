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
	buf map[string]*ring
}

// ring holds one VM's events. It grows to the recorder's cap, and after that a new event overwrites the
// oldest in place: adding an event costs one copy of it, however full the ring is. (Reslicing and copying
// the whole ring on every add made a busy host allocate megabytes per event, and the garbage collector
// spent most of the daemon's CPU scanning what was thrown away.)
type ring struct {
	evs  []event.Event
	next int // once full: the index of the oldest event, which the next add replaces
}

func (g *ring) add(e event.Event, cap int) {
	if len(g.evs) < cap {
		g.evs = append(g.evs, e)
		return
	}
	g.evs[g.next] = e
	g.next++
	if g.next == len(g.evs) {
		g.next = 0
	}
}

// each calls f for every event, oldest first.
func (g *ring) each(f func(event.Event)) {
	if g == nil {
		return
	}
	for _, e := range g.evs[g.next:] {
		f(e)
	}
	for _, e := range g.evs[:g.next] {
		f(e)
	}
}

func New(cap int) *Recorder {
	if cap <= 0 {
		cap = DefaultCap
	}
	return &Recorder{cap: cap, buf: map[string]*ring{}}
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
	g := r.buf[k]
	if g == nil {
		g = &ring{}
		r.buf[k] = g
	}
	g.add(e, r.cap)
}

// Window returns events for vm whose timestamp is within d of now, oldest first.
// vm "_" or "" returns every VM, still filtered by time.
func (r *Recorder) Window(vm string, d time.Duration, now time.Time) []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-d)
	var out []event.Event
	keep := func(e event.Event) {
		if !e.TS.Before(cutoff) {
			out = append(out, e)
		}
	}
	if vm == "" || vm == "_" {
		for _, g := range r.buf {
			g.each(keep)
		}
		return out
	}
	r.buf[vm].each(keep)
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
		r.buf[k].each(func(e event.Event) { out = append(out, e) })
	}
	return out
}
