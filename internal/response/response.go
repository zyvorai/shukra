// Package response decides what to do when a detection fires. The only thing it can do to a VM is isolate it,
// and by default it does not even do that: it proposes, and a person approves. Every guardrail lives here so
// that one place says what an automatic action may and may not do:
//
//   - a response acts only on the detections it names (or, if it names none, on high ones, and then only
//     ever proposes);
//   - some VMs can be protected from every response;
//   - a VM is left alone for a cooldown after it was acted on, and one already isolated is not isolated twice;
//   - only so many isolations may be carried out automatically in an hour;
//   - an isolation can release itself after a while, and that timer survives a restart;
//   - nothing is done unless the daemon can really isolate: without a management allow list every action is
//     refused, as isolate itself is;
//   - everything decided, refused or done is recorded, and announced as a detection so a person hears of it.
package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/shukra/internal/detect"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

// Store keeps what the engine decided across a restart, and the evidence for each action.
type Store interface {
	Append(state.Action) error
	SaveBundle(id string, b []byte) error
	LoadBundle(id string) ([]byte, bool)
}

const (
	maxActions   = 500 // actions kept in memory, oldest dropped
	maxBundles   = 50  // incident bundles kept in memory
	queueSize    = 256
	bundleWindow = 15 * time.Minute
)

// Engine is the response engine. It is safe for concurrent use.
type Engine struct {
	st    *state.State
	store Store
	now   func() time.Time

	mu      sync.Mutex
	cfg     []detect.Response
	guard   detect.Guardrails
	actions []*state.Action // oldest first
	next    int
	last    map[string]time.Time // vm|response -> when it was last acted on
	hourly  []time.Time          // when automatic isolations were carried out
	bundles map[string][]byte
	order   []string // bundle ids, oldest first
	queue   chan event.Event
	dropped uint64
}

// New returns an engine over a state. store may be nil, in which case nothing survives a restart.
func New(st *state.State, store Store) *Engine {
	return &Engine{st: st, store: store, now: time.Now, last: map[string]time.Time{}, bundles: map[string][]byte{}, queue: make(chan event.Event, queueSize)}
}

// SetConfig applies the responses and guardrails of a rules file.
func (e *Engine) SetConfig(c *detect.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg, e.guard = c.Responses, c.Guard
}

// Enabled implements state.ActionsView.
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cfg) > 0
}

// OnDetection is the hook the state calls for every detection. It only queues: acting on a VM asks the kernel
// for something, and the event path must not wait for that. If the queue is full the detection is dropped and
// counted, which can only mean a storm, and the daily cap on isolations would have held anyway.
func (e *Engine) OnDetection(d event.Event) {
	select {
	case e.queue <- d:
	default:
		e.mu.Lock()
		e.dropped++
		e.mu.Unlock()
	}
}

// Dropped is how many detections were dropped because the queue was full.
func (e *Engine) Dropped() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dropped
}

// Run consumes detections and, every few seconds, lets proposals lapse and isolations release, until stop closes.
func (e *Engine) Run(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case d := <-e.queue:
			e.Handle(d)
		case <-t.C:
			e.Tick(e.now())
		}
	}
}

// Restore loads what was decided before a restart. Of several records for one id the last is the truth.
func (e *Engine) Restore(list []state.Action) {
	e.mu.Lock()
	defer e.mu.Unlock()
	latest := map[string]state.Action{}
	var order []string
	for _, a := range list {
		if _, seen := latest[a.ID]; !seen {
			order = append(order, a.ID)
		}
		latest[a.ID] = a
	}
	e.actions = nil
	for _, id := range order {
		a := latest[id]
		e.actions = append(e.actions, &a)
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "a-")); err == nil && n > e.next {
			e.next = n
		}
		if a.Status == "executed" && a.Mode == "enforce" && !a.DryRun && e.now().Sub(a.Decided) < time.Hour {
			e.hourly = append(e.hourly, a.Decided)
		}
		if a.Status != "" {
			e.last[a.VM+"|"+a.Response] = a.Created
		}
	}
	if len(e.actions) > maxActions {
		e.actions = e.actions[len(e.actions)-maxActions:]
	}
}

func (e *Engine) find(id string) *state.Action {
	for _, a := range e.actions {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func (e *Engine) record(a *state.Action) {
	if e.store != nil {
		_ = e.store.Append(*a)
	}
}

// announce puts a decision in front of people as a detection, so it reaches the console, the alert sinks and a
// person who has to approve it. A response never answers its own announcements.
func (e *Engine) announce(kind, severity string, a *state.Action, msg string) {
	e.st.AddEvent(event.Event{
		Kind: event.KindDetection, TS: e.now().UTC(), Rule: "action-" + kind, Severity: severity,
		VM: event.VM{Name: a.VM}, Message: msg,
	})
}

func (e *Engine) protected(vm string) bool {
	for _, v := range e.guard.NeverIsolate {
		if v == vm {
			return true
		}
	}
	return false
}

func (e *Engine) isolated(vm string) bool {
	for _, v := range e.st.ActiveIsolations() {
		if v == vm {
			return true
		}
	}
	return false
}

// autoLastHour is how many isolations were carried out automatically in the last hour. Caller holds e.mu.
func (e *Engine) autoLastHour(now time.Time) int {
	keep := e.hourly[:0]
	for _, t := range e.hourly {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	e.hourly = keep
	return len(keep)
}

// Handle answers one detection.
func (e *Engine) Handle(d event.Event) {
	if d.VM.Name == "" || strings.HasPrefix(d.Rule, "action-") {
		return
	}
	now := e.now()
	e.mu.Lock()
	var resp *detect.Response
	for i := range e.cfg {
		if e.cfg[i].Answers(d.Rule, d.Severity) {
			resp = &e.cfg[i]
			break
		}
	}
	if resp == nil {
		e.mu.Unlock()
		return
	}
	r := *resp
	guard := e.guard
	vm := d.VM.Name
	// Already waiting for a decision about this VM, or acted on lately, or already isolated: nothing to add.
	for _, a := range e.actions {
		if a.VM == vm && a.Status == "pending" {
			e.mu.Unlock()
			return
		}
	}
	if t, ok := e.last[vm+"|"+r.Name]; ok && now.Sub(t) < r.Cooldown {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	if e.isolated(vm) {
		return
	}

	e.mu.Lock()
	e.next++
	a := &state.Action{
		ID: "a-" + strconv.Itoa(e.next), VM: vm, Response: r.Name, Mode: r.Mode, DryRun: r.DryRun,
		Rule: d.Rule, Severity: d.Severity, Message: d.Message, Created: now.UTC(),
	}
	e.last[vm+"|"+r.Name] = now
	e.actions = append(e.actions, a)
	if len(e.actions) > maxActions {
		e.actions = e.actions[len(e.actions)-maxActions:]
	}
	e.mu.Unlock()
	e.captureBundle(a)

	refuse := func(guardrail, why string) {
		e.mu.Lock()
		a.Status, a.Guardrail, a.Result, a.Decided = "refused", guardrail, why, now.UTC()
		e.mu.Unlock()
		e.record(a)
		e.announce("refused", "low", a, fmt.Sprintf("%s: response %q would have isolated %s for %s, and did not: %s", a.ID, a.Response, vm, d.Rule, why))
	}
	switch {
	case e.protected(vm):
		refuse("never_isolate", vm+" is protected: no response may isolate it")
		return
	case r.DryRun:
		e.mu.Lock()
		a.Status, a.Decided, a.Result = "dry_run", now.UTC(), "dry run: nothing was changed"
		e.mu.Unlock()
		e.record(a)
		e.announce("dry-run", "low", a, fmt.Sprintf("%s: response %q would have isolated %s for %s (dry run: nothing changed)", a.ID, a.Response, vm, d.Rule))
		return
	}
	if mode, _, why := e.st.Enforcement(); mode != "tcx" {
		refuse("isolate_unavailable", "isolate is not enabled: "+why)
		return
	}
	if r.Mode == "enforce" {
		e.mu.Lock()
		over := e.autoLastHour(now) >= guard.MaxPerHour
		e.mu.Unlock()
		if over {
			refuse("max_per_hour", fmt.Sprintf("%d automatic isolations were already carried out in the last hour", guard.MaxPerHour))
			return
		}
		e.execute(a, r, "auto:"+r.Name+":"+a.ID, true)
		return
	}
	e.mu.Lock()
	a.Status, a.Expires = "pending", now.Add(r.Expire).UTC()
	e.mu.Unlock()
	e.record(a)
	e.announce("proposed", "medium", a, fmt.Sprintf("%s: response %q proposes isolating %s for %s: approve or reject it (shukractl approve %s) within %s", a.ID, a.Response, vm, d.Rule, a.ID, r.Expire))
}

// execute isolates the VM and records the outcome. auto says whether it counts against the hourly cap.
func (e *Engine) execute(a *state.Action, r detect.Response, actor string, auto bool) {
	iso := e.st.Isolate(a.VM, actor)
	now := e.now().UTC()
	e.mu.Lock()
	a.Decided = now
	if a.DecidedBy == "" {
		a.DecidedBy = actor // an automatic action is decided by the response that made it
	}
	if !iso.Applied {
		a.Status, a.Guardrail, a.Result = "refused", "isolate_refused", iso.Reason
	} else {
		a.Status, a.Result = "executed", "isolated: "+iso.Reason
		if auto {
			e.hourly = append(e.hourly, now)
		}
		if r.ReleaseAfter > 0 {
			a.ReleaseAt = now.Add(r.ReleaseAfter)
		}
	}
	e.mu.Unlock()
	e.record(a)
	if a.Status == "executed" {
		msg := fmt.Sprintf("%s: response %q isolated %s for %s (%s)", a.ID, a.Response, a.VM, a.Rule, actor)
		if !a.ReleaseAt.IsZero() {
			msg += fmt.Sprintf("; it releases itself at %s", a.ReleaseAt.Format(time.RFC3339))
		}
		e.announce("executed", "high", a, msg)
		return
	}
	e.announce("refused", "low", a, fmt.Sprintf("%s: isolating %s was refused: %s", a.ID, a.VM, a.Result))
}

func (e *Engine) responseNamed(name string) (detect.Response, bool) {
	for _, r := range e.cfg {
		if r.Name == name {
			return r, true
		}
	}
	return detect.Response{}, false
}

// Approve carries out a proposed isolation, on a person's word. The guardrails are checked again: the world may
// have changed since it was proposed.
func (e *Engine) Approve(id, actor string) (state.Action, error) {
	now := e.now()
	e.mu.Lock()
	a := e.find(id)
	if a == nil {
		e.mu.Unlock()
		return state.Action{}, state.ErrActionNotFound
	}
	if a.Status != "pending" {
		out := *a
		e.mu.Unlock()
		return out, state.ErrActionNotPending
	}
	if now.After(a.Expires) {
		a.Status, a.Decided, a.Result = "expired", now.UTC(), "the proposal lapsed before anyone decided"
		out := *a
		e.mu.Unlock()
		e.record(&out)
		return out, fmt.Errorf("the proposal expired at %s", out.Expires.Format(time.RFC3339))
	}
	r, ok := e.responseNamed(a.Response)
	if !ok {
		r = detect.Response{Name: a.Response} // the response was removed from the rules since: the person still decided
	}
	prot := e.protected(a.VM)
	a.DecidedBy = actor
	e.mu.Unlock()
	switch {
	case prot:
		e.mu.Lock()
		a.Status, a.Guardrail, a.Result, a.Decided = "refused", "never_isolate", a.VM+" is protected: no response may isolate it", now.UTC()
		out := *a
		e.mu.Unlock()
		e.record(&out)
		return out, errors.New(out.Result)
	case e.isolated(a.VM):
		e.mu.Lock()
		a.Status, a.Result, a.Decided = "refused", a.VM+" is already isolated", now.UTC()
		out := *a
		e.mu.Unlock()
		e.record(&out)
		return out, errors.New(out.Result)
	}
	e.execute(a, r, fmt.Sprintf("approved by %s (%s, %s)", actor, a.Response, a.ID), false)
	e.mu.Lock()
	out := *a
	e.mu.Unlock()
	if out.Status != "executed" {
		return out, errors.New(out.Result)
	}
	return out, nil
}

// Reject declines a proposal. Nothing is done to the VM.
func (e *Engine) Reject(id, actor string) (state.Action, error) {
	e.mu.Lock()
	a := e.find(id)
	if a == nil {
		e.mu.Unlock()
		return state.Action{}, state.ErrActionNotFound
	}
	if a.Status != "pending" {
		out := *a
		e.mu.Unlock()
		return out, state.ErrActionNotPending
	}
	a.Status, a.Decided, a.DecidedBy, a.Result = "rejected", e.now().UTC(), actor, "rejected by "+actor
	out := *a
	e.mu.Unlock()
	e.record(&out)
	e.announce("rejected", "low", &out, fmt.Sprintf("%s: %s rejected isolating %s", out.ID, actor, out.VM))
	return out, nil
}

// Tick lets proposals lapse and releases isolations whose time has come. The release time is stored with the
// action, so a restart neither forgets nor extends it: an isolation that should have ended while the daemon was
// down ends on the first tick.
func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	var expired, due []*state.Action
	for _, a := range e.actions {
		switch {
		case a.Status == "pending" && now.After(a.Expires):
			a.Status, a.Decided, a.Result = "expired", now.UTC(), "the proposal lapsed before anyone decided"
			expired = append(expired, a)
		case a.Status == "executed" && !a.ReleaseAt.IsZero() && !now.Before(a.ReleaseAt):
			due = append(due, a)
		}
	}
	e.mu.Unlock()
	for _, a := range expired {
		e.record(a)
		e.announce("expired", "low", a, fmt.Sprintf("%s: the proposal to isolate %s lapsed without a decision", a.ID, a.VM))
	}
	for _, a := range due {
		iso := e.st.Release(a.VM, "auto:"+a.ID+":timer")
		e.mu.Lock()
		a.Status, a.Released = "released", now.UTC()
		a.Result = "released after " + strings.TrimSpace(now.Sub(a.Decided).Round(time.Second).String())
		if !iso.Applied {
			a.Result += " (the release request said: " + iso.Reason + ")"
		}
		e.mu.Unlock()
		e.record(a)
		e.announce("released", "low", a, fmt.Sprintf("%s: %s was released again, as its response said it would be", a.ID, a.VM))
	}
}

// captureBundle stores the evidence for an action: the incident bundle for the VM as it was when the action was
// made. A proposal needs it so the person deciding has something to decide on.
func (e *Engine) captureBundle(a *state.Action) {
	b, err := json.MarshalIndent(e.st.Incident(a.VM, time.Time{}, bundleWindow), "", "  ")
	if err != nil {
		return
	}
	e.mu.Lock()
	e.bundles[a.ID] = b
	e.order = append(e.order, a.ID)
	for len(e.order) > maxBundles {
		delete(e.bundles, e.order[0])
		e.order = e.order[1:]
	}
	e.mu.Unlock()
	if e.store != nil {
		_ = e.store.SaveBundle(a.ID, b)
	}
}

// Bundle implements state.ActionsView.
func (e *Engine) Bundle(id string) ([]byte, bool) {
	e.mu.Lock()
	b, ok := e.bundles[id]
	e.mu.Unlock()
	if ok {
		return b, true
	}
	if e.store != nil {
		return e.store.LoadBundle(id)
	}
	return nil, false
}

// List implements state.ActionsView.
func (e *Engine) List(all bool) []state.Action {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []state.Action{}
	for i := len(e.actions) - 1; i >= 0; i-- {
		if all || e.actions[i].Status == "pending" {
			out = append(out, *e.actions[i])
		}
	}
	return out
}

// Counts implements state.ActionsView.
func (e *Engine) Counts() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]int{}
	for _, a := range e.actions {
		out[a.Status]++
	}
	return out
}

// Modes implements state.ActionsView.
func (e *Engine) Modes() (propose, enforce, dryRun int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.cfg {
		switch {
		case r.DryRun:
			dryRun++
		case r.Mode == "enforce":
			enforce++
		default:
			propose++
		}
	}
	return
}

// Statuses is every status an action can have, in the order they are listed.
func Statuses() []string {
	return []string{"pending", "executed", "released", "refused", "rejected", "expired", "dry_run"}
}
