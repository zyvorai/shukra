// Package baseline learns what each VM normally does, so that what is new for that VM can be noticed
// without anyone writing a rule for it: the networks it talks to, the DNS names it looks up, and who
// connects to it. It is the opposite of a watchlist: nothing is known to be bad, only new.
//
// A VM is observed for a learning period from the first time it is seen, during which everything is only
// recorded. After that the first sighting of an item is reported once, and then recorded, so it is never
// new again. What a guest can do to this is bounded: it can fill a VM's sets up to a fixed size and then only
// turn them over (the oldest is dropped), and a VM can raise only so many new-item alerts a day.
package baseline

import (
	"sort"
	"sync"
	"time"
)

// Kind is one thing a VM is learned by.
type Kind string

const (
	// Destination is a network the guest connected or sent to: an IPv4 /24 or an IPv6 /64.
	Destination Kind = "destination"
	// DNSSuffix is the registrable part of a name the guest looked up: "example.co.uk", "example.com".
	DNSSuffix Kind = "dns-suffix"
	// InboundPeer is a network that connected in to the guest.
	InboundPeer Kind = "inbound-peer"
)

// Kinds is every kind, in the order they are shown.
var Kinds = []Kind{Destination, DNSSuffix, InboundPeer}

// Options are the limits a Store works to.
type Options struct {
	// Learn is how long a VM is only observed, from the first time it is seen.
	Learn time.Duration
	// MaxItems bounds each kind's set per VM. Past it the item unseen for longest is dropped.
	MaxItems int
	// MaxAge is how long an unseen item is remembered. After it, the item is new again when it returns.
	MaxAge time.Duration
	// MaxAlertsPerDay bounds the new-item alerts one VM can raise in a rolling day. Items past it are learned
	// and counted, not reported.
	MaxAlertsPerDay int
}

// DefaultOptions is what a rules file that says only "baselines:" gets.
func DefaultOptions() Options {
	return Options{Learn: 24 * time.Hour, MaxItems: 2048, MaxAge: 30 * 24 * time.Hour, MaxAlertsPerDay: 20}
}

// Item is one learned thing and when it was first and last seen.
type Item struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// Verdict is what observing an item meant.
type Verdict int

const (
	// Learning: the VM is still in its learning period. The item was recorded.
	Learning Verdict = iota
	// Known: seen before.
	Known
	// New: the first sighting after learning. It was recorded, and the caller should report it.
	New
	// Capped: new, and recorded, but the VM has used its alerts for the day. Not to be reported.
	Capped
)

func (v Verdict) String() string {
	return [...]string{"learning", "known", "new", "capped"}[v]
}

// Result is the outcome of one observation.
type Result struct {
	Verdict Verdict
	// CapReached is true on the one observation that used up the VM's alerts for the day, so the caller can say
	// once that more are being held back.
	CapReached bool
}

type vmBase struct {
	Since      time.Time                 `json:"since"`
	Sets       map[Kind]map[string]*Item `json:"sets"`
	DayStart   time.Time                 `json:"dayStart"`
	AlertsDay  int                       `json:"alertsToday"`
	Alerts     uint64                    `json:"alerts"`
	Suppressed uint64                    `json:"suppressed"`
}

// Store holds every VM's baseline. It is safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	opts  Options
	vms   map[string]*vmBase
	dirty bool
}

// NewStore returns an empty Store with the given limits.
func NewStore(o Options) *Store {
	return &Store{opts: normalise(o), vms: map[string]*vmBase{}}
}

func normalise(o Options) Options {
	d := DefaultOptions()
	if o.Learn <= 0 {
		o.Learn = d.Learn
	}
	if o.MaxItems <= 0 {
		o.MaxItems = d.MaxItems
	}
	if o.MaxAge <= 0 {
		o.MaxAge = d.MaxAge
	}
	if o.MaxAlertsPerDay <= 0 {
		o.MaxAlertsPerDay = d.MaxAlertsPerDay
	}
	return o
}

// SetOptions changes the limits. A VM already past its learning period stays past it; a longer Learn only
// applies to VMs first seen after.
func (s *Store) SetOptions(o Options) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts = normalise(o)
}

// Options returns the limits in force.
func (s *Store) Options() Options {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts
}

func (s *Store) vm(name string, now time.Time) *vmBase {
	b := s.vms[name]
	if b == nil {
		b = &vmBase{Since: now, Sets: map[Kind]map[string]*Item{}, DayStart: now}
		s.vms[name] = b
		s.dirty = true
	}
	return b
}

// Observe records an item for a VM and says what it meant. An empty item is ignored (Known): it is not a
// thing to learn.
func (s *Store) Observe(vm string, k Kind, item string, now time.Time) Result {
	if item == "" || vm == "" {
		return Result{Verdict: Known}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.vm(vm, now)
	set := b.Sets[k]
	if set == nil {
		set = map[string]*Item{}
		b.Sets[k] = set
	}
	s.dirty = true
	if it, ok := set[item]; ok && now.Sub(it.Last) <= s.opts.MaxAge {
		it.Last = now
		return Result{Verdict: Known}
	}
	set[item] = &Item{First: now, Last: now}
	s.trim(set)
	if now.Sub(b.Since) < s.opts.Learn {
		return Result{Verdict: Learning}
	}
	if now.Sub(b.DayStart) >= 24*time.Hour {
		b.DayStart, b.AlertsDay = now, 0
	}
	if b.AlertsDay >= s.opts.MaxAlertsPerDay {
		b.Suppressed++
		return Result{Verdict: Capped}
	}
	b.AlertsDay++
	b.Alerts++
	return Result{Verdict: New, CapReached: b.AlertsDay == s.opts.MaxAlertsPerDay}
}

// trim drops the item unseen for longest while the set is over its bound.
func (s *Store) trim(set map[string]*Item) {
	for len(set) > s.opts.MaxItems {
		var oldest string
		var when time.Time
		for k, it := range set {
			if oldest == "" || it.Last.Before(when) || (it.Last.Equal(when) && k < oldest) {
				oldest, when = k, it.Last
			}
		}
		delete(set, oldest)
	}
}

// Forget starts a VM's baseline over: its learning period begins again and everything learned is dropped. It
// says whether the VM was known.
func (s *Store) Forget(vm string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.vms[vm]
	delete(s.vms, vm)
	s.dirty = s.dirty || ok
	return ok
}

// Prune drops items unseen for longer than MaxAge and returns how many it dropped. A VM's learning period is
// not affected.
func (s *Store) Prune(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.vms {
		for _, set := range b.Sets {
			for k, it := range set {
				if now.Sub(it.Last) > s.opts.MaxAge {
					delete(set, k)
					n++
				}
			}
		}
	}
	if n > 0 {
		s.dirty = true
	}
	return n
}

// KindCount is how many items of a kind a VM has learned.
type KindCount struct {
	Kind  Kind `json:"kind"`
	Count int  `json:"count"`
}

// VMStatus is where one VM's baseline stands.
type VMStatus struct {
	VM         string      `json:"vm"`
	Since      time.Time   `json:"since"`
	Learning   bool        `json:"learning"`
	LearnUntil time.Time   `json:"learnUntil"`
	Counts     []KindCount `json:"counts"`
	AlertsDay  int         `json:"alertsToday"`
	Alerts     uint64      `json:"alerts"`
	Suppressed uint64      `json:"suppressed"`
}

// Status is the state of every VM's baseline, or of one VM, sorted by name. Counts always lists every kind.
func (s *Store) Status(vm string, now time.Time) []VMStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []VMStatus{}
	for name, b := range s.vms {
		if vm != "" && name != vm {
			continue
		}
		st := VMStatus{VM: name, Since: b.Since, LearnUntil: b.Since.Add(s.opts.Learn), AlertsDay: b.AlertsDay, Alerts: b.Alerts, Suppressed: b.Suppressed}
		st.Learning = now.Before(st.LearnUntil)
		if now.Sub(b.DayStart) >= 24*time.Hour {
			st.AlertsDay = 0
		}
		for _, k := range Kinds {
			st.Counts = append(st.Counts, KindCount{Kind: k, Count: len(b.Sets[k])})
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VM < out[j].VM })
	return out
}

// Learned is one item of a VM's baseline.
type Learned struct {
	Kind  Kind      `json:"kind"`
	Item  string    `json:"item"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// Items lists what a VM has learned, most recently seen first, at most limit of them (0 is all). It is nil for
// a VM that is not known, and [] for one that has learned nothing.
func (s *Store) Items(vm string, limit int) []Learned {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.vms[vm]
	if b == nil {
		return nil
	}
	out := []Learned{}
	for k, set := range b.Sets {
		for item, it := range set {
			out = append(out, Learned{Kind: k, Item: item, First: it.First, Last: it.Last})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Item < out[j].Item
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Data is a Store on disk.
type Data struct {
	Version int                `json:"version"`
	VMs     map[string]*vmBase `json:"vms"`
}

// Snapshot returns a copy of everything learned, and clears the store's dirty flag. ok is false when nothing
// has changed since the last snapshot, so a caller can skip the write.
func (s *Store) Snapshot() (d Data, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return Data{}, false
	}
	d = Data{Version: 1, VMs: make(map[string]*vmBase, len(s.vms))}
	for name, b := range s.vms {
		c := *b
		c.Sets = make(map[Kind]map[string]*Item, len(b.Sets))
		for k, set := range b.Sets {
			cs := make(map[string]*Item, len(set))
			for item, it := range set {
				v := *it
				cs[item] = &v
			}
			c.Sets[k] = cs
		}
		d.VMs[name] = &c
	}
	s.dirty = false
	return d, true
}

// Restore replaces what the store holds with d. Data from a version this build does not know is ignored.
func (s *Store) Restore(d Data) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Version != 1 {
		return
	}
	s.vms = map[string]*vmBase{}
	for name, b := range d.VMs {
		if b == nil {
			continue
		}
		if b.Sets == nil {
			b.Sets = map[Kind]map[string]*Item{}
		}
		s.vms[name] = b
	}
	s.dirty = false
}
