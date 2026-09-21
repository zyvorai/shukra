// Package policy is the per-VM egress policy: which networks a VM may start connections to, learned from what
// it has been seen to do, tried out in audit mode, and only then enforced.
//
// The kernel program does the judging (bpf/tap.bpf.c). This package decides what is put there and when, and it
// is built so that a wrong policy cannot quietly cut a VM off:
//
//   - Audit is the way in. It counts and reports what would be dropped and drops nothing.
//   - Enforcing needs the management allow list (the floor no policy can take away), needs a record of the
//     policy that survives a restart, and needs either a confirmation timer, after which the VM goes back to
//     what it had unless a person confirms, or an explicit choice that there is none.
//   - A record is written before the kernel is changed, so the record is never behind what is enforced, and a
//     change that fails is put back.
//   - What the record says is what the kernel is made to do, after a VM comes back with a new tap and after a
//     restart; the kernel keeps enforcing without the daemon, and the timer that would revert it is in the
//     record, so a daemon that was down when it ran out reverts on its first pass.
package policy

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/observe"
	"github.com/zyvorai/shukra/internal/state"
)

const (
	// MaxAllow is the most networks one VM's policy may list. The kernel map holds 16384 for all VMs together.
	MaxAllow = 1024
	// MinConfirm and MaxConfirm bound how long an enforcing policy waits to be confirmed.
	MinConfirm = 30 * time.Second
	MaxConfirm = 24 * time.Hour
	tickEvery  = 2 * time.Second
)

// Mode is what a policy does: off, audit (report, drop nothing) or enforce.
type Mode string

const (
	Off     Mode = "off"
	Audit   Mode = "audit"
	Enforce Mode = "enforce"
)

func (m Mode) kernel() uint8 {
	switch m {
	case Audit:
		return 1
	case Enforce:
		return 2
	}
	return 0
}

func modeOf(b uint8) Mode {
	switch b {
	case 1:
		return Audit
	case 2:
		return Enforce
	}
	return Off
}

// Revert is where an enforcing policy goes back to if nobody confirms it: Mode Off means it is removed.
type Revert struct {
	Until  time.Time `json:"until"`
	Mode   Mode      `json:"mode"`
	Allow  []string  `json:"allow,omitempty"`
	Source string    `json:"source,omitempty"`
}

// Policy is the record of one VM's egress policy. It is what is saved, and what the kernel is made to match.
type Policy struct {
	VM      string    `json:"vm"`
	Mode    Mode      `json:"mode"`
	Allow   []string  `json:"allow"`
	Source  string    `json:"source"`
	By      string    `json:"by,omitempty"`
	Applied time.Time `json:"applied"`
	KeyID   string    `json:"keyId,omitempty"`
	Role    string    `json:"role,omitempty"`
	Label   string    `json:"label,omitempty"`
	Remote  string    `json:"remote,omitempty"`
	Request string    `json:"requestId,omitempty"`
	Op      string    `json:"op,omitempty"`
	Revert  *Revert   `json:"revert,omitempty"`
}

// Store keeps the policies across restarts. Save is given all of them, and must not return until they are safe.
type Store interface {
	Save([]Policy) error
}

// Kernel is the tap program's egress policy. *observe.EgressKernel is one.
type Kernel interface {
	Available() (bool, string)
	CanEnforce() (bool, string)
	Set(tap string, mode uint8, prefixes []netip.Prefix) error
	Mode(tap string) uint8
	Stats() []observe.EgressCounters
}

// Engine holds every VM's policy.
type Engine struct {
	st    *state.State
	k     Kernel
	store Store
	now   func() time.Time

	mu     sync.Mutex
	pol    map[string]*Policy
	logged map[string]bool
}

// New makes an engine. With a nil store policies are kept in memory only, and enforcing is refused.
func New(st *state.State, k Kernel, store Store) *Engine {
	return &Engine{st: st, k: k, store: store, now: time.Now, pol: map[string]*Policy{}, logged: map[string]bool{}}
}

// Persisted implements state.PolicyView.
func (e *Engine) Persisted() bool { return e.store != nil }

// Restore loads policies that were saved. It does not touch the kernel: Reconcile does, once the VMs are known.
func (e *Engine) Restore(ps []Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range ps {
		p := p
		if p.VM == "" || (p.Mode != Audit && p.Mode != Enforce) {
			continue
		}
		if _, err := parseAllow(p.Allow); err != nil {
			continue
		}
		e.pol[p.VM] = &p
	}
}

// Run reconciles until stop is closed.
func (e *Engine) Run(stop <-chan struct{}) {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.Reconcile()
		}
	}
}

// parseAllow reads networks: a CIDR, or a bare address (which is a /32 or a /128). The result is canonical (host
// bits cleared), without duplicates, and sorted.
func parseAllow(in []string) ([]netip.Prefix, error) {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(s, "/") {
			var err error
			if p, err = netip.ParsePrefix(s); err != nil {
				return nil, fmt.Errorf("%w: %q is not a network (192.0.2.0/24, or 2001:db8::/32)", state.ErrPolicyBad, s)
			}
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%w: %q is not an address or a network", state.ErrPolicyBad, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if a := p.Addr(); a.Is4In6() {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
			if !p.IsValid() {
				return nil, fmt.Errorf("%w: %q is wider than an IPv4 network", state.ErrPolicyBad, s)
			}
		}
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out, nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// announcement is a detection to raise once the engine's lock is released.
type announcement struct {
	vm             event.VM
	rule, severity string
	message        string
}

func (e *Engine) announce(as []announcement) {
	for _, a := range as {
		e.st.AddEvent(event.Event{Kind: event.KindDetection, TS: e.now().UTC(), VM: a.vm, Rule: a.rule, Severity: a.severity, Message: a.message})
	}
}

func (e *Engine) find(name string) (vmTaps []string, vm event.VM, ok bool) {
	for _, v := range e.st.VMs() {
		if v.Name == name {
			return v.Taps, event.VM{Name: v.Name, UUID: v.UUID, Runtime: v.Runtime}, true
		}
	}
	return nil, event.VM{Name: name}, false
}

func (e *Engine) saveLocked() error {
	if e.store == nil {
		return nil
	}
	all := make([]Policy, 0, len(e.pol))
	for _, p := range e.pol {
		all = append(all, *p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].VM < all[j].VM })
	return e.store.Save(all)
}

// setTaps puts each tap under a mode and list, and says which did not take it.
func (e *Engine) setTaps(taps []string, mode Mode, allow []string) (failed []string) {
	prefixes, _ := parseAllow(allow)
	for _, t := range taps {
		if err := e.k.Set(t, mode.kernel(), prefixes); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", t, err))
		}
	}
	return failed
}

// Apply puts a VM under a policy, changes it, or (with mode off) lifts it.
func (e *Engine) Apply(vmName string, req state.PolicyRequest, actor string) (state.PolicyRow, error) {
	var mode Mode
	switch Mode(req.Mode) {
	case Off, Audit, Enforce:
		mode = Mode(req.Mode)
	default:
		return state.PolicyRow{}, fmt.Errorf("%w: mode %q is not off, audit or enforce", state.ErrPolicyBad, req.Mode)
	}
	if mode == Off {
		return e.Remove(vmName, actor)
	}
	var confirm time.Duration
	if req.Confirm != "" {
		d, err := time.ParseDuration(req.Confirm)
		if err != nil || d < MinConfirm || d > MaxConfirm {
			return state.PolicyRow{}, fmt.Errorf("%w: confirm %q is not a duration from %s to %s", state.ErrPolicyBad, req.Confirm, MinConfirm, MaxConfirm)
		}
		confirm = d
	}
	if req.Permanent && confirm > 0 {
		return state.PolicyRow{}, fmt.Errorf("%w: give a confirmation time or permanent, not both", state.ErrPolicyBad)
	}

	e.mu.Lock()
	row, as, err := e.applyLocked(vmName, mode, req, confirm, actor)
	e.mu.Unlock()
	e.announce(as)
	return row, err
}

func (e *Engine) applyLocked(vmName string, mode Mode, req state.PolicyRequest, confirm time.Duration, actor string) (state.PolicyRow, []announcement, error) {
	taps, vm, present := e.find(vmName)
	if !present {
		return state.PolicyRow{}, nil, fmt.Errorf("%w: no VM named %q is in the current scan", state.ErrPolicyNotFound, vmName)
	}
	if len(taps) == 0 {
		return state.PolicyRow{}, nil, fmt.Errorf("%w: %s has no tap interface (user-mode networking has none), so there is nothing to put a policy on", state.ErrPolicyRefused, vmName)
	}
	if ok, why := e.k.Available(); !ok {
		return state.PolicyRow{}, nil, fmt.Errorf("%w: the tap program is not loaded: %s", state.ErrPolicyRefused, why)
	}
	prev := e.pol[vmName]

	// The list: the one given, the one the baseline suggests, or the one the VM has.
	var allow []string
	source := "manual"
	switch {
	case len(req.Allow) > 0:
		ps, err := parseAllow(req.Allow)
		if err != nil {
			return state.PolicyRow{}, nil, err
		}
		allow = prefixStrings(ps)
	case req.FromBaseline:
		prop, err := e.learnLocked(vmName)
		if err != nil {
			return state.PolicyRow{}, nil, err
		}
		allow, source = prop.Allow, "baseline"
	case prev != nil:
		allow, source = prev.Allow, prev.Source
	default:
		return state.PolicyRow{}, nil, fmt.Errorf("%w: no list of networks: give --allow, or --from-baseline to take what the VM has been seen to talk to", state.ErrPolicyBad)
	}
	if len(allow) > MaxAllow {
		return state.PolicyRow{}, nil, fmt.Errorf("%w: %d networks is more than the %d one VM may list", state.ErrPolicyBad, len(allow), MaxAllow)
	}

	if mode == Enforce {
		if ok, why := e.k.CanEnforce(); !ok {
			return state.PolicyRow{}, nil, fmt.Errorf("%w: enforcing needs the management allow list (-isolate-allow), the floor that no policy can take away: %s", state.ErrPolicyRefused, why)
		}
		if e.store == nil {
			return state.PolicyRow{}, nil, fmt.Errorf("%w: enforcing needs -data-dir, so that the record of the policy survives a restart: the kernel keeps enforcing without the daemon, and a policy nobody has a record of cannot be reverted", state.ErrPolicyRefused)
		}
		if len(allow) == 0 {
			return state.PolicyRow{}, nil, fmt.Errorf("%w: an empty list would cut the VM off from everything but the management network: that is what isolate is for", state.ErrPolicyRefused)
		}
		if confirm == 0 && !req.Permanent {
			return state.PolicyRow{}, nil, fmt.Errorf("%w: enforcing needs --confirm <duration>, after which the VM goes back to what it had unless a person confirms, or --permanent", state.ErrPolicyBad)
		}
	}

	now := e.now().UTC()
	who := state.ParseActor(actor)
	next := &Policy{VM: vmName, Mode: mode, Allow: allow, Source: source, By: who.Principal(), Applied: now,
		KeyID: who.KeyID, Role: who.Role, Label: who.Label, Remote: who.Remote, Request: who.RequestID, Op: who.Op}
	if mode == Enforce && confirm > 0 {
		r := &Revert{Until: now.Add(confirm), Mode: Off}
		switch {
		case prev != nil && prev.Revert != nil:
			// Changing an enforcing policy that was never confirmed: what it goes back to is still what
			// it was before any of this, not the change in between.
			r = &Revert{Until: now.Add(confirm), Mode: prev.Revert.Mode, Allow: prev.Revert.Allow, Source: prev.Revert.Source}
		case prev != nil:
			r = &Revert{Until: now.Add(confirm), Mode: prev.Mode, Allow: prev.Allow, Source: prev.Source}
		}
		next.Revert = r
	}

	// The record first, then the kernel: the record is never behind what is enforced.
	e.pol[vmName] = next
	if err := e.saveLocked(); err != nil {
		e.restore(vmName, prev)
		return state.PolicyRow{}, nil, fmt.Errorf("the policy was not saved, so it was not applied: %w", err)
	}
	failed := e.setTaps(taps, mode, allow)
	if len(failed) == len(taps) {
		// Nothing took it: put back what there was, in the record and, best effort, in the kernel.
		e.restore(vmName, prev)
		_ = e.saveLocked()
		if prev != nil {
			e.setTaps(taps, prev.Mode, prev.Allow)
		} else {
			e.setTaps(taps, Off, nil)
		}
		return state.PolicyRow{}, nil, fmt.Errorf("the tap program did not take the policy: %s", strings.Join(failed, "; "))
	}

	verb := "is auditing"
	sev := "low"
	if mode == Enforce {
		verb, sev = "is now enforcing", "medium"
	}
	msg := fmt.Sprintf("%s %s an egress policy of %d networks (set by %s, from %s)", vmName, verb, len(allow), who.Principal(), source)
	if next.Revert != nil {
		msg += fmt.Sprintf("; it goes back to %s at %s unless confirmed (shukractl policy confirm %s)", describe(next.Revert.Mode, len(next.Revert.Allow)), next.Revert.Until.Format(time.RFC3339), vmName)
	}
	row := e.rowLocked(next, present)
	if len(failed) > 0 {
		row.Problem = "some taps did not take it: " + strings.Join(failed, "; ")
	}
	return row, []announcement{{vm, "policy-applied", sev, msg}}, nil
}

func describe(m Mode, n int) string {
	if m == Off {
		return "no policy"
	}
	return fmt.Sprintf("%s with %d networks", m, n)
}

func (e *Engine) restore(vm string, prev *Policy) {
	if prev == nil {
		delete(e.pol, vm)
		return
	}
	e.pol[vm] = prev
}

// Confirm makes an enforcing policy that is waiting stay.
func (e *Engine) Confirm(vmName, actor string) (state.PolicyRow, error) {
	e.mu.Lock()
	p := e.pol[vmName]
	if p == nil {
		e.mu.Unlock()
		return state.PolicyRow{}, fmt.Errorf("%w: %s has no policy", state.ErrPolicyNotFound, vmName)
	}
	if p.Revert == nil {
		e.mu.Unlock()
		return state.PolicyRow{}, fmt.Errorf("%w: nothing waits for confirmation on %s", state.ErrPolicyRefused, vmName)
	}
	held := *p.Revert
	p.Revert = nil
	who := state.ParseActor(actor)
	p.By, p.KeyID, p.Role, p.Label, p.Remote, p.Request, p.Op = who.Principal(), who.KeyID, who.Role, who.Label, who.Remote, who.RequestID, who.Op
	if err := e.saveLocked(); err != nil {
		p.Revert = &held
		e.mu.Unlock()
		return state.PolicyRow{}, fmt.Errorf("the confirmation was not saved, so it did not take effect: %w", err)
	}
	_, vm, present := e.find(vmName)
	row := e.rowLocked(p, present)
	e.mu.Unlock()
	e.announce([]announcement{{vm, "policy-confirmed", "low", fmt.Sprintf("%s's %s egress policy was confirmed by %s: it stays", vmName, p.Mode, who.Principal())}})
	return row, nil
}

// Remove lifts a VM's policy, whether or not there is a record of one: the kernel is put right either way.
func (e *Engine) Remove(vmName, actor string) (state.PolicyRow, error) {
	e.mu.Lock()
	taps, vm, present := e.find(vmName)
	prev := e.pol[vmName]
	kernelHad := false
	for _, t := range taps {
		if e.k.Mode(t) != 0 {
			kernelHad = true
		}
	}
	if prev == nil && !kernelHad {
		e.mu.Unlock()
		return state.PolicyRow{}, fmt.Errorf("%w: %s has no policy", state.ErrPolicyNotFound, vmName)
	}
	// The kernel first: lifting a policy is the safe direction, so if the record cannot be saved the VM is
	// still not held by a policy nobody can see.
	failed := e.setTaps(taps, Off, nil)
	delete(e.pol, vmName)
	saveErr := e.saveLocked()
	e.mu.Unlock()
	if saveErr != nil {
		log.Printf("policy: removing %s: the record could not be saved: %v", vmName, saveErr)
	}
	row := state.PolicyRow{VM: vmName, Mode: string(Off), Allow: []string{}, Present: present, Taps: []state.PolicyTap{}}
	if len(failed) > 0 {
		row.Problem = "some taps did not release it: " + strings.Join(failed, "; ")
	}
	e.announce([]announcement{{vm, "policy-removed", "low", fmt.Sprintf("%s's egress policy was removed by %s", vmName, state.ParseActor(actor).Principal())}})
	return row, nil
}

// Reconcile is one pass: a policy that was not confirmed in time goes back, and the kernel is made to match the
// record on every tap of every VM in the scan (a VM that came back with a new tap, or a restart).
func (e *Engine) Reconcile() {
	var as []announcement
	e.mu.Lock()
	now := e.now().UTC()
	names := make([]string, 0, len(e.pol))
	for n := range e.pol {
		names = append(names, n)
	}
	sort.Strings(names)
	changed := false
	for _, n := range names {
		p := e.pol[n]
		if p.Revert == nil || now.Before(p.Revert.Until) {
			continue
		}
		taps, vm, _ := e.find(n)
		r := *p.Revert
		if r.Mode == Off {
			delete(e.pol, n)
			e.setTaps(taps, Off, nil)
			as = append(as, announcement{vm, "policy-reverted", "medium", fmt.Sprintf("%s's egress policy was not confirmed in time and has been removed", n)})
		} else {
			p.Mode, p.Allow, p.Source, p.Revert, p.Applied = r.Mode, r.Allow, r.Source, nil, now
			e.setTaps(taps, p.Mode, p.Allow)
			as = append(as, announcement{vm, "policy-reverted", "medium", fmt.Sprintf("%s's enforcing egress policy was not confirmed in time and has gone back to %s", n, describe(r.Mode, len(r.Allow)))})
		}
		changed = true
	}
	if changed {
		if err := e.saveLocked(); err != nil {
			log.Printf("policy: saving after a revert: %v", err)
		}
	}
	for _, v := range e.st.VMs() {
		p := e.pol[v.Name]
		want := Off
		var allow []string
		if p != nil {
			want, allow = p.Mode, p.Allow
		}
		for _, t := range v.Taps {
			if p == nil || modeOf(e.k.Mode(t)) == want {
				continue
			}
			if failed := e.setTaps([]string{t}, want, allow); len(failed) > 0 && !e.logged[t+failed[0]] {
				e.logged[t+failed[0]] = true
				log.Printf("policy: making %s match %s's %s policy: %s", t, v.Name, want, failed[0])
			}
		}
	}
	e.mu.Unlock()
	e.announce(as)
}

// Orphans are taps the kernel applies a policy on when there is no record of one.
func (e *Engine) Orphans() []state.PolicyOrphan {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []state.PolicyOrphan{}
	for _, v := range e.st.VMs() {
		if e.pol[v.Name] != nil {
			continue
		}
		for _, t := range v.Taps {
			if m := e.k.Mode(t); m != 0 {
				out = append(out, state.PolicyOrphan{VM: v.Name, Tap: t, Mode: string(modeOf(m))})
			}
		}
	}
	return out
}

// Learn proposes a policy from what the VM's baseline has seen it connect to.
func (e *Engine) Learn(vmName string) (state.PolicyProposal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.learnLocked(vmName)
}

func (e *Engine) learnLocked(vmName string) (state.PolicyProposal, error) {
	bv := e.st.Baselines()
	if bv == nil || !bv.Enabled() {
		return state.PolicyProposal{}, fmt.Errorf("%w: learned baselines are off, so there is nothing to propose from: add a baselines: section to the rules file (docs/baselines.md), or give the networks with --allow", state.ErrPolicyRefused)
	}
	items := bv.Items(vmName, 0)
	if items == nil {
		return state.PolicyProposal{}, fmt.Errorf("%w: the baseline has not seen a VM named %q", state.ErrPolicyNotFound, vmName)
	}
	var seen []string
	for _, it := range items {
		if it.Kind == baseline.Destination {
			seen = append(seen, it.Item)
		}
	}
	ps, _ := parseAllow(seen)
	prop := state.PolicyProposal{VM: vmName, Allow: prefixStrings(ps), Current: []string{}, Added: []string{}, Removed: []string{}}
	for _, s := range bv.Status(vmName, e.now()) {
		if s.VM == vmName && s.Learning {
			prop.Learning = true
			prop.Note = "the VM is still inside its baseline's learning period (until " + s.LearnUntil.Format(time.RFC3339) + "): what it has not done yet is not on this list"
		}
	}
	if len(prop.Allow) == 0 && prop.Note == "" {
		prop.Note = "the VM has not been seen connecting anywhere"
	}
	have := map[string]bool{}
	if p := e.pol[vmName]; p != nil {
		prop.Current = append([]string{}, p.Allow...)
		for _, a := range p.Allow {
			have[a] = true
		}
	}
	want := map[string]bool{}
	for _, a := range prop.Allow {
		want[a] = true
		if !have[a] {
			prop.Added = append(prop.Added, a)
		}
	}
	for _, a := range prop.Current {
		if !want[a] {
			prop.Removed = append(prop.Removed, a)
		}
	}
	return prop, nil
}

// List implements state.PolicyView.
func (e *Engine) List() []state.PolicyRow {
	e.mu.Lock()
	defer e.mu.Unlock()
	present := map[string]bool{}
	for _, v := range e.st.VMs() {
		present[v.Name] = true
	}
	names := make([]string, 0, len(e.pol))
	for n := range e.pol {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]state.PolicyRow, 0, len(names))
	for _, n := range names {
		out = append(out, e.rowLocked(e.pol[n], present[n]))
	}
	return out
}

// Get implements state.PolicyView.
func (e *Engine) Get(vmName string) (state.PolicyRow, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.pol[vmName]
	if p == nil {
		return state.PolicyRow{}, false
	}
	_, _, present := e.find(vmName)
	return e.rowLocked(p, present), true
}

func (e *Engine) rowLocked(p *Policy, present bool) state.PolicyRow {
	row := state.PolicyRow{VM: p.VM, Mode: string(p.Mode), Allow: append([]string{}, p.Allow...), Source: p.Source, By: p.By, Applied: p.Applied, Present: present, Taps: []state.PolicyTap{},
		KeyID: p.KeyID, Role: p.Role, Label: p.Label, Remote: p.Remote, RequestID: p.Request, Op: p.Op}
	if p.Revert != nil {
		row.Revert = &state.PolicyRevert{Until: p.Revert.Until, To: describe(p.Revert.Mode, len(p.Revert.Allow))}
	}
	if !present {
		return row
	}
	taps, _, _ := e.find(p.VM)
	stats := map[string]observe.EgressCounters{}
	for _, s := range e.k.Stats() {
		stats[s.Tap] = s
	}
	for _, t := range taps {
		s := stats[t]
		km := modeOf(e.k.Mode(t))
		row.Taps = append(row.Taps, state.PolicyTap{Tap: t, Kernel: string(km), Checked: s.Checked, AuditPkts: s.AuditPkts, AuditBytes: s.AuditBytes, DroppedPkts: s.DropPkts, DroppedBytes: s.DropBytes})
		if km != p.Mode && row.Problem == "" {
			row.Problem = fmt.Sprintf("the kernel has %s in mode %s, and the policy says %s", t, km, p.Mode)
		}
	}
	return row
}
