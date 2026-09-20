package state

import (
	"fmt"
	"log"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
)

// The in-memory history is six minutes, which answers "why is it slow now". An incident that is found an hour
// later needs an older view, so a coarse copy of the counters is kept on disk: one snapshot every RollEvery,
// holding each VM's counters summed over its threads and its vCPU threads on their own (the only threads
// whose wait is a finding). A verdict for a past time is built the same way as a live one, from the
// difference between two of these instead of between now and a recent snapshot. It says how coarse that is.
const (
	// RollEvery is how often a snapshot is stored.
	RollEvery = 5 * time.Minute
	// DefaultAtWindow is how far back a verdict for a past time looks unless asked otherwise.
	DefaultAtWindow = 15 * time.Minute
	// MaxAtWindow is the longest such window.
	MaxAtWindow = 6 * time.Hour
)

// RollupSnap is the counters of every VM at one moment, cumulative since the daemon attached.
type RollupSnap struct {
	At       time.Time           `json:"at"`
	VMs      []VMRoll            `json:"vms"`
	Drops    map[string]DropRoll `json:"drops,omitempty"`    // by tap; absent when the drops program was not measuring
	Outcomes map[string]Outcomes `json:"outcomes,omitempty"` // by tap; absent when the tap program was not on
}

// VMRoll is one VM in a snapshot.
type VMRoll struct {
	Name    string             `json:"name"`
	UUID    string             `json:"uuid,omitempty"`
	Runtime string             `json:"runtime,omitempty"`
	PID     int                `json:"pid"`
	Taps    []string           `json:"taps,omitempty"`
	Total   aggregate.Counters `json:"total"`
	VCPUs   []VCPURoll         `json:"vcpus,omitempty"`
}

// VCPURoll is one vCPU thread, with only the counters a scheduling verdict reads.
type VCPURoll struct {
	TID  int                `json:"tid"`
	Comm string             `json:"comm,omitempty"`
	C    aggregate.Counters `json:"c"`
}

// DropRoll is what the kernel dropped on one tap, and how much of it was Shukra's own isolation.
type DropRoll struct {
	Reasons map[string]uint64 `json:"reasons"`
	Shukra  uint64            `json:"shukra"`
}

// RollupStore keeps snapshots. Around returns the newest snapshot at or before at, and the newest at or
// before that snapshot's time minus window. Either may be nil when the store has none that old.
type RollupStore interface {
	Append(RollupSnap) error
	Around(at time.Time, window time.Duration) (cur, base *RollupSnap, err error)
}

// SetRollup gives the state somewhere to keep snapshots. Without one, no history beyond the six minutes in
// memory is kept, and a verdict for a past time says so.
func (s *State) SetRollup(r RollupStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollup = r
}

// dueRollLocked builds a snapshot if one is due. Caller holds s.mu.
func (s *State) dueRollLocked(now time.Time) (*RollupSnap, RollupStore) {
	if s.rollup == nil || len(s.vms) == 0 || (!s.lastRoll.IsZero() && now.Sub(s.lastRoll) < RollEvery) {
		return nil, nil
	}
	s.lastRoll = now
	snap := RollupSnap{At: now.UTC()}
	for _, vm := range s.vms {
		v := VMRoll{Name: vm.Name, UUID: vm.UUID, Runtime: vm.Runtime, PID: vm.PID, Taps: append([]string(nil), vm.Taps...)}
		var all []aggregate.Counters
		seen := map[uint32]bool{}
		for _, tid := range vm.Threads {
			id := identity.PID32(tid)
			if c, ok := s.byPID[id]; ok && id != 0 {
				all = append(all, c)
				seen[id] = true
			}
		}
		v.Total = aggregate.Sum(all)
		for _, t := range vm.ThreadInfo {
			id := identity.PID32(t.TID)
			if t.Role != "vcpu" || id == 0 || !seen[id] {
				continue
			}
			v.VCPUs = append(v.VCPUs, VCPURoll{TID: t.TID, Comm: t.Comm, C: vcpuView(s.byPID[id])})
		}
		snap.VMs = append(snap.VMs, v)
	}
	if s.dropSource != nil && s.programAttachedLocked("drops") {
		var taps []TapStat
		if s.tapSource != nil {
			taps = s.tapSource()
		}
		snap.Drops = map[string]DropRoll{}
		for tap, d := range snapsFrom(s.sinceStartLocked(taps), s.dropSource()) {
			snap.Drops[tap] = DropRoll{Reasons: d.reasons, Shukra: d.shukra}
		}
	}
	if s.tapSource != nil && s.programAttachedLocked("tap") {
		snap.Outcomes = map[string]Outcomes{}
		for _, t := range s.tapSource() {
			snap.Outcomes[t.Name] = t.Outcomes
		}
	}
	return &snap, s.rollup
}

func (s *State) appendRoll(store RollupStore, snap RollupSnap) {
	if err := store.Append(snap); err != nil {
		s.mu.Lock()
		warned := s.rollWarned
		s.rollWarned = true
		s.mu.Unlock()
		if !warned { // once, not every five minutes
			log.Printf("history: cannot store a snapshot, so a verdict for a past time will be short: %v", err)
		}
	}
}

// vcpuView keeps what a scheduling verdict reads from a vCPU thread. The rest of a thread's counters (exit
// reasons, block histograms) are in the VM's total.
func vcpuView(c aggregate.Counters) aggregate.Counters {
	return aggregate.Counters{
		OnCPUNs: c.OnCPUNs, WakeupDelayNs: c.WakeupDelayNs, WakeupCount: c.WakeupCount,
		SchedHist: append([]uint64(nil), c.SchedHist...), PreemptNs: c.PreemptNs, PreemptCount: c.PreemptCount,
		Preemptors: cloneLabels(c.Preemptors),
	}
}

func cloneLabels(m map[string]uint64) map[string]uint64 {
	if m == nil {
		return nil
	}
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func rollVM(s *RollupSnap, name string) (VMRoll, bool) {
	if s != nil {
		for _, v := range s.VMs {
			if v.Name == name {
				return v, true
			}
		}
	}
	return VMRoll{}, false
}

func rollDrops(m map[string]DropRoll) map[string]dropSnap {
	out := make(map[string]dropSnap, len(m))
	for tap, d := range m {
		out[tap] = dropSnap{reasons: d.Reasons, shukra: d.Shukra}
	}
	return out
}

// noHistory is the whole verdict when there is nothing to look at, with the reason in words.
func noHistory(name string, at time.Time, why string) Explain {
	return Explain{
		VM: identity.VM{Name: name}, Question: "why was this VM slow?", Window: "none", At: at.UTC().Format(time.RFC3339),
		Findings: []Finding{{Cause: "no_history", Confidence: "high", Summary: why}},
		Basis:    "Nothing about that time is stored, so nothing is claimed.",
		Evidence: []string{}, Missing: []string{"stored history for that time"}, Events: []event.Event{},
	}
}

// ExplainAt builds the verdict for a past time from the stored snapshots: what the counters did over the
// window that ended at at. The answer is as fine as the snapshots, and says so.
func (s *State) ExplainAt(name string, at time.Time, window time.Duration) Explain {
	s.mu.RLock()
	store := s.rollup
	s.mu.RUnlock()
	if store == nil {
		return noHistory(name, at, "No history is kept: the daemon has nowhere to store snapshots. Start it with -data-dir to keep about a day of them.")
	}
	if window <= 0 {
		window = DefaultAtWindow
	}
	window = min(max(window, RollEvery), MaxAtWindow)
	cur, base, err := store.Around(at, window)
	switch {
	case err != nil:
		return noHistory(name, at, "The stored history could not be read: "+err.Error())
	case cur == nil:
		return noHistory(name, at, "No snapshot is stored at or before "+at.UTC().Format(time.RFC3339)+". History starts when the daemon first ran with -data-dir, and only the newest is kept.")
	case at.Sub(cur.At) > 2*RollEvery:
		return noHistory(name, at, fmt.Sprintf("The nearest snapshot is from %s, %s before the time asked about, so it says nothing about then. The daemon was probably not running.", cur.At.UTC().Format(time.RFC3339), at.Sub(cur.At).Round(time.Second)))
	case base == nil || cur.At.Sub(base.At) < RollEvery:
		return noHistory(name, at, "Not enough history before that time: a verdict needs a snapshot at least "+RollEvery.String()+" older than the one it stands on.")
	}
	curVM, found := rollVM(cur, name)
	if !found {
		ex := noHistory(name, at, "No VM with that name was running at that time.")
		ex.Findings[0].Cause = "unknown_vm"
		return ex
	}
	baseVM, _ := rollVM(base, name) // a VM new in the window has no base: all of it is the window's
	span := cur.At.Sub(base.At)
	vendor := s.cpuVendorLocked()

	syn := identity.VM{Name: name, UUID: curVM.UUID, Runtime: curVM.Runtime, PID: curVM.PID, Threads: []int{curVM.PID}, Taps: curVM.Taps}
	pid := identity.PID32(curVM.PID)
	window1 := map[uint32]aggregate.Counters{pid: aggregate.Delta(curVM.Total, baseVM.Total)}
	rows := windowRows(syn, window1, vendor)
	life := windowRows(syn, map[uint32]aggregate.Counters{pid: curVM.Total}, vendor)
	carryMeasured(rows.kvm, rows.sched, rows.block, life.kvm, life.sched, life.block)

	// The vCPU threads are per-thread rows, so a slow vCPU can be told from the rest of the VM.
	synT := identity.VM{Name: name}
	perT := map[uint32]aggregate.Counters{}
	baseV := map[int]aggregate.Counters{}
	for _, v := range baseVM.VCPUs {
		baseV[v.TID] = v.C
	}
	for _, v := range curVM.VCPUs {
		synT.Threads = append(synT.Threads, v.TID)
		synT.ThreadInfo = append(synT.ThreadInfo, identity.Thread{TID: v.TID, Comm: v.Comm, Role: "vcpu"})
		perT[identity.PID32(v.TID)] = aggregate.Delta(v.C, baseV[v.TID])
	}
	threads := aggregate.SchedThreads([]identity.VM{synT}, perT, name)

	var dropTaps []DropTap
	if cur.Drops != nil {
		dropTaps = joinTaps([]identity.VM{syn}, subSnaps(rollDrops(cur.Drops), rollDrops(base.Drops)), name)
	}
	var conns *Outcomes
	if cur.Outcomes != nil {
		var o Outcomes
		for _, tap := range curVM.Taps {
			o = addOutcomes(o, subOutcomes(cur.Outcomes[tap], base.Outcomes[tap]))
		}
		conns = &o
	}

	over := span.Round(time.Second).String()
	tapOn := cur.Outcomes != nil
	return Explain{
		VM: syn, Question: "why was this VM slow?", Window: over, At: at.UTC().Format(time.RFC3339),
		Resolution: fmt.Sprintf("%s snapshots: the verdict stands on %s and %s", RollEvery, base.At.UTC().Format(time.RFC3339), cur.At.UTC().Format(time.RFC3339)),
		Findings:   diagnose(true, rows.kvm, rows.sched, threads, rows.block, rows.net, dropTaps, conns),
		Basis:      "Over " + over + " of stored history. Latencies come from log2 buckets, so each can read up to 2x high. They are the QEMU process's, not the guest's.",
		Evidence:   evidenceFor(true, life.kvm, life.sched, life.block, rows.net, rows.sched, rows.block),
		Missing:    missingFor(tapOn),
		Events:     s.Recorder(name, min(window, 10*time.Minute), at),
	}
}

// evidenceFor says what the verdict stands on. life are the lifetime rows, which say whether a program is
// measuring at all, and d are the rows for the window the verdict weighs.
func evidenceFor(found bool, kvm []aggregate.KVMRow, sched []aggregate.SchedRow, block []aggregate.BlockRow, net []aggregate.NetRow,
	dsched []aggregate.SchedRow, dblock []aggregate.BlockRow) []string {
	var evidence []string
	if found {
		evidence = append(evidence, "Identity comes from the QEMU command line, not from inside the guest.")
	} else {
		evidence = append(evidence, "No QEMU process with that name is in the current /proc scan.")
	}
	if len(kvm) > 0 && kvm[0].Measured {
		evidence = append(evidence, "KVM exit counters are present for this thread group.")
	} else {
		evidence = append(evidence, "KVM exit counters are not populated. The kvm program may be detached.")
	}
	if len(sched) > 0 && sched[0].Measured {
		evidence = append(evidence, "Scheduler on-CPU and wakeup-delay counters are present.")
	}
	if len(block) > 0 && block[0].Measured {
		evidence = append(evidence, "Block latency histogram is present for the QEMU iothread, not the guest filesystem.")
		if len(dblock) > 0 && (dblock[0].ReadP99Ns >= aggregate.SlowBlockNS || dblock[0].WriteP99Ns >= aggregate.SlowBlockNS) {
			evidence = append(evidence, "Block p99 is at least 10ms on the QEMU iothread.")
		}
	}
	if len(dsched) > 0 && dsched[0].Measured && dsched[0].WakeupCount > 0 && dsched[0].WakeupDelayNs/dsched[0].WakeupCount >= aggregate.SlowWakeupNS {
		evidence = append(evidence, "Mean wakeup delay is at least 20ms.")
	}
	if len(net) > 0 && (net[0].Connects > 0 || net[0].Retransmits > 0) {
		evidence = append(evidence, "TCP connects are from the QEMU process. They are not guest flows.")
	}
	return evidence
}

// missingFor is what this build cannot see, whatever the verdict says.
func missingFor(tapAttached bool) []string {
	missing := []string{"CPU steal as the guest counts it (Shukra measures the host's view: how long the vCPUs were preempted)", "in-guest process identity"}
	if !tapAttached {
		missing = append([]string{"guest tap attribution (TCX on the VM tap is not attached)"}, missing...)
	}
	return missing
}

// IncidentEvents caps the recorder events in an incident bundle, so a busy VM's bundle stays a size a person can attach
// to a ticket.
const IncidentEvents = 500

// Incident is everything Shukra knows about one VM around one moment, in one document to attach to a ticket:
// the verdict, the detections, what the recorder saw, and every isolate request. It holds VM names,
// addresses and DNS names, so it is as sensitive as the event list. It never holds an API key: nothing in it
// comes from the daemon's configuration except the isolate allow list.
type Incident struct {
	Product     string        `json:"product"`
	GeneratedAt time.Time     `json:"generatedAt"`
	VM          string        `json:"vm"`
	At          string        `json:"at"`     // the moment the bundle is about; "now" for a live one
	Window      string        `json:"window"` // how far back it looks
	Explain     Explain       `json:"explain"`
	Detections  []event.Event `json:"detections"`
	Events      []event.Event `json:"events"`
	Isolations  []Isolation   `json:"isolations"`
	Enforcement string        `json:"enforcement"`
	AllowList   []string      `json:"allowList"`
	Programs    []Program     `json:"programs"`
	Note        string        `json:"note"`
}

// Incident builds the bundle. A zero at is now, and uses the live history; otherwise the verdict stands on
// the stored snapshots, like ExplainAt.
func (s *State) Incident(name string, at time.Time, window time.Duration) Incident {
	now := s.now().UTC()
	live := at.IsZero()
	if live {
		at = now
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	window = min(window, MaxAtWindow)
	inc := Incident{
		Product: "shukra", GeneratedAt: now, VM: name, At: "now", Window: window.String(),
		Detections: []event.Event{}, Events: []event.Event{}, Isolations: []Isolation{}, AllowList: []string{},
		Note: "Contains VM names, addresses and DNS names. Treat it like the event list.",
	}
	if live {
		inc.Explain = s.ExplainOver(name, now, min(window, MaxExplainWindow))
	} else {
		inc.At = at.UTC().Format(time.RFC3339)
		inc.Explain = s.ExplainAt(name, at, window)
	}
	from := at.Add(-window)
	for _, d := range s.Detections(name) {
		if !d.TS.Before(from) && !d.TS.After(at) {
			inc.Detections = append(inc.Detections, d)
		}
	}
	inc.Events = s.Recorder(name, window, at)
	if len(inc.Events) > IncidentEvents {
		inc.Events = inc.Events[len(inc.Events)-IncidentEvents:]
	}
	for _, i := range s.Isolations() {
		if i.VM == name && !i.Audit.TS.Before(from) && !i.Audit.TS.After(at) {
			inc.Isolations = append(inc.Isolations, i)
		}
	}
	mode, allow, _ := s.Enforcement()
	inc.Enforcement = mode
	if allow != nil {
		inc.AllowList = allow
	}
	inc.Programs = s.Programs()
	return inc
}
