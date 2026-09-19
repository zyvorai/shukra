// Package state is the userspace snapshot shukrad serves.
// Enforcement is recorded here and never applied to a datapath.
package state

import (
	"sync"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/recorder"
	"github.com/zyvorai/shukra/internal/version"
)

// Persister receives what should survive a restart. State calls it after
// releasing its lock, so an implementation may do file I/O.
type Persister interface {
	Detection(event.Event)
	Isolation(Isolation)
}

// SinkStat is delivery accounting for one alert sink.
type SinkStat struct {
	Name    string
	Sent    uint64
	Failed  uint64
	Dropped uint64
}

// Program is one eBPF object and whether it is attached.
type Program struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Audit is the isolate record. Applied is always false in this build.
type Audit struct {
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	VM     string    `json:"vm"`
	Result string    `json:"result"`
}

// Isolation is the response to an isolate request.
type Isolation struct {
	VM          string   `json:"vm"`
	Enforcement string   `json:"enforcement"`
	Applied     bool     `json:"applied"`
	Taps        []string `json:"taps,omitempty"`
	Reason      string   `json:"reason"`
	Audit       Audit    `json:"audit"`
}

// Explain is the evidence available for one VM, plus what this build cannot say.
type Explain struct {
	VM       identity.VM `json:"vm"`
	Question string      `json:"question"`
	// Findings are the host-side causes the counters support, best supported first.
	Findings []Finding `json:"findings"`
	// Window is how far back the findings look: a duration, or "lifetime" when
	// there was not enough history yet or none was asked for.
	Window   string        `json:"window"`
	Basis    string        `json:"basis"`
	Evidence []string      `json:"evidence"`
	Missing  []string      `json:"missing"`
	Events   []event.Event `json:"events"`
}

// Status is the board shukractl status prints.
type Status struct {
	Version          string `json:"version"`
	Product          string `json:"product"`
	Tagline          string `json:"tagline"`
	Mode             string `json:"mode"`
	Datapath         string `json:"datapath"`
	Healthy          bool   `json:"healthy"`
	VMs              int    `json:"vms"`
	ProgramsAttached int    `json:"programsAttached"`
	ProgramsTotal    int    `json:"programsTotal"`
	Detections       int    `json:"detections"`
	Summary          string `json:"summary"`
}

// State is safe for the HTTP server and the agent to share.
type State struct {
	mu            sync.RWMutex
	started       time.Time
	hostname      string
	vms           []identity.VM
	programs      []Program
	byPID         map[uint32]aggregate.Counters
	detections    []event.Event
	events        []event.Event
	isolations    []Isolation
	rec           *recorder.Recorder
	seq           uint64
	connects      map[string]uint64
	ready         bool
	config        ConfigInfo
	rulesErr      string
	kernelRelease func() string
	history       []snapshot
	clock         func() time.Time
	enforcer      Enforcer
	tapSource     func() []TapStat
	cpuVendor     string
	persist       Persister
	hooks         []func(event.Event)
	suppressed    uint64
	sinkStats     func() []SinkStat
	changed       chan struct{}
}

// MaxEvents bounds the in-memory event and detection lists.
const MaxEvents = 2048

func New(hostname string) *State {
	return &State{
		started:  time.Now().UTC(),
		hostname: hostname,
		byPID:    map[uint32]aggregate.Counters{},
		connects: map[string]uint64{},
		changed:  make(chan struct{}),
		rec:      recorder.New(recorder.DefaultCap),
		programs: []Program{
			{Name: "kvm", Status: "detached", Detail: "not attached yet"},
			{Name: "sched", Status: "detached", Detail: "not attached yet"},
			{Name: "block", Status: "detached", Detail: "not attached yet"},
			{Name: "net", Status: "detached", Detail: "not attached yet"},
			{Name: "tap", Status: "detached", Detail: "not attached yet"},
		},
	}
}

func (s *State) SetVMs(vms []identity.VM) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vms = append([]identity.VM(nil), vms...)
}

func (s *State) VMs() []identity.VM {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]identity.VM(nil), s.vms...)
}

// SetPrograms records attach state. It is called after a completed scan, so the
// first call is also what makes the daemon ready.
func (s *State) SetPrograms(p []Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.programs = append([]Program(nil), p...)
	s.ready = true
}

// Ready reports whether the first scan finished.
func (s *State) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

// Seq is the Seq of the newest stored event, or 0 before the first.
func (s *State) Seq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq
}

// Changed returns a channel that is closed the next time an event is added.
// Take it before reading events so an event added in between is not missed.
func (s *State) Changed() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.changed
}

func (s *State) Programs() []Program {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Program(nil), s.programs...)
}

func (s *State) SetCounters(by map[uint32]aggregate.Counters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byPID = by
	s.recordLocked(s.now())
}

func (s *State) AddEvent(e event.Event) {
	event.Normalize(&e)
	s.mu.Lock()
	s.seq++
	e.Seq = s.seq
	s.events = append(s.events, e)
	if len(s.events) > MaxEvents {
		s.events = append([]event.Event(nil), s.events[len(s.events)-MaxEvents:]...)
	}
	switch e.Kind {
	case event.KindDetection:
		s.detections = append(s.detections, e)
		if len(s.detections) > MaxEvents {
			s.detections = append([]event.Event(nil), s.detections[len(s.detections)-MaxEvents:]...)
		}
	case event.KindTCPConnect:
		// Counted here so the total keeps growing after the event list wraps.
		name := e.VM.Name
		if name == "" {
			name = aggregate.Host
		}
		s.connects[name]++
	}
	s.rec.Add(e)
	close(s.changed)
	s.changed = make(chan struct{})
	p, hooks := s.persist, s.hooks
	s.mu.Unlock()
	if e.Kind != event.KindDetection {
		return
	}
	if p != nil {
		p.Detection(e)
	}
	for _, fn := range hooks {
		fn(e)
	}
}

func (s *State) Events(vm string) []event.Event {
	return s.EventsSince(vm, 0)
}

// EventsSince returns stored events with Seq greater than since. Events that
// have already aged out of the list are not returned.
func (s *State) EventsSince(vm string, since uint64) []event.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []event.Event
	for _, e := range s.events {
		if e.Seq > since && (vm == "" || e.VM.Name == vm) {
			out = append(out, e)
		}
	}
	return out
}

func (s *State) Detections(vm string) []event.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []event.Event
	for _, e := range s.detections {
		if vm == "" || e.VM.Name == vm {
			out = append(out, e)
		}
	}
	return out
}

// OnDetection registers fn to be called with each new detection, after State
// releases its lock. fn must not block: it runs on the event path. Restored
// detections do not call it.
func (s *State) OnDetection(fn func(event.Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = append(s.hooks, fn)
}

// AddSuppressed counts detections a rule held back as repeats.
func (s *State) AddSuppressed(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suppressed += n
}

// Suppressed is how many detections were held back as repeats.
func (s *State) Suppressed() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.suppressed
}

// SetSinkStats sets where delivery counts for the alert sinks come from.
func (s *State) SetSinkStats(fn func() []SinkStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinkStats = fn
}

// SinkStats is delivery accounting for each configured sink, if any.
func (s *State) SinkStats() []SinkStat {
	s.mu.RLock()
	fn := s.sinkStats
	s.mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// SetPersister sets where detections and isolations are also written. Call
// Restore first so restored records are not written twice.
func (s *State) SetPersister(p Persister) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persist = p
}

// Restore loads records saved by a previous run. It moves seq forward to the
// highest restored value so new events never reuse a seq a client has seen.
// Events are re-normalized, so a hand-edited file cannot claim guest attribution.
func (s *State) Restore(detections []event.Event, isolations []Isolation, recorded []event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range detections {
		event.Normalize(&e)
		s.detections = append(s.detections, e)
		s.seq = max(s.seq, e.Seq)
	}
	if len(s.detections) > MaxEvents {
		s.detections = append([]event.Event(nil), s.detections[len(s.detections)-MaxEvents:]...)
	}
	s.isolations = append(s.isolations, isolations...)
	if len(s.isolations) > MaxEvents {
		s.isolations = append([]Isolation(nil), s.isolations[len(s.isolations)-MaxEvents:]...)
	}
	for _, e := range recorded {
		s.rec.Add(e)
		s.seq = max(s.seq, e.Seq)
	}
}

// RecorderSnapshot is every event the flight recorder holds, for saving.
func (s *State) RecorderSnapshot() []event.Event {
	return s.rec.Snapshot()
}

func (s *State) Recorder(vm string, window time.Duration, now time.Time) []event.Event {
	return s.rec.Window(vm, window, now)
}

// Isolations is the audit trail of isolate requests, oldest first.
func (s *State) Isolations() []Isolation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Isolation(nil), s.isolations...)
}

func (s *State) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	att := 0
	for _, p := range s.programs {
		if p.Status == "attached" {
			att++
		}
	}
	summary := "observe: host traces only, guest tap attribution not attached"
	for _, p := range s.programs {
		if p.Name == "tap" && p.Status == "attached" {
			summary = "observe: host traces, and guest traffic on the VM taps (" + p.Detail + ")"
		}
	}
	return Status{
		Version: version.Version, Product: version.Product, Tagline: version.Tagline,
		Mode: "observe", Datapath: "tracepoint-kprobe", Healthy: true,
		VMs: len(s.vms), ProgramsAttached: att, ProgramsTotal: len(s.programs),
		Detections: len(s.detections),
		Summary:    summary,
	}
}

func (s *State) cpuVendorLocked() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cpuVendor
}

// SetCPUVendor records the host CPU vendor_id ("GenuineIntel", "AuthenticAMD").
// KVM exit reasons are only named where the numbering for that vendor is known.
func (s *State) SetCPUVendor(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cpuVendor = v
}

func (s *State) KVM(vm string) []aggregate.KVMRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := aggregate.KVM(s.vms, s.byPID, vm)
	aggregate.NameReasons(rows, s.cpuVendor)
	return rows
}

func (s *State) Sched(vm string) []aggregate.SchedRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return aggregate.Sched(s.vms, s.byPID, vm)
}

func (s *State) SchedThreads(vm string) []aggregate.ThreadRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return aggregate.SchedThreads(s.vms, s.byPID, vm)
}

func (s *State) Block(vm string) []aggregate.BlockRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return aggregate.Block(s.vms, s.byPID, vm)
}

func (s *State) Net(vm string) []aggregate.NetRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := aggregate.Net(s.vms, s.byPID, vm)
	counts := map[string]uint64{}
	for name, n := range s.connects {
		if vm == "" || name == vm {
			counts[name] = n
		}
	}
	seen := map[string]bool{}
	for i := range rows {
		// The kernel counter and the event count are the same connects seen two
		// ways, so take the larger. The map is exact; the ring can lose events.
		// With no program attached only the events exist.
		rows[i].Connects = max(rows[i].Connects, counts[rows[i].VM])
		seen[rows[i].VM] = true
	}
	for name, n := range counts {
		if seen[name] || n == 0 {
			continue
		}
		attr := event.AttributionUnattributed
		note := "Not a QEMU thread. Not guest traffic."
		if name != aggregate.Host {
			attr = event.AttributionQEMU
			note = "Connects and retransmits from the QEMU process, not the guest. Tap/TCX attribution is not attached."
		}
		rows = append(rows, aggregate.NetRow{
			VM: name, Connects: n, Attribution: attr, GuestAttributed: false, Note: note,
		})
	}
	return rows
}

func (s *State) FindVM(name string) (identity.VM, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, vm := range s.vms {
		if vm.Name == name {
			return vm, true
		}
	}
	return identity.VM{}, false
}

// Explain looks at the last DefaultExplainWindow.
func (s *State) Explain(name string, now time.Time) Explain {
	return s.ExplainOver(name, now, DefaultExplainWindow)
}

// ExplainOver builds the verdict from what happened over roughly the last window.
// A zero window, or too little history so far, uses the counters since the daemon
// attached, and the result says which it used.
func (s *State) ExplainOver(name string, now time.Time, window time.Duration) Explain {
	vm, _ := s.FindVM(name)
	// What is present, and whether each program is measuring at all, is a lifetime
	// fact: a quiet minute must not read as a detached program.
	kvm := s.KVM(name)
	sched := s.Sched(name)
	block := s.Block(name)
	net := s.Net(name)
	threads := s.SchedThreads(name)

	// What the verdict weighs is the window.
	dkvm, dsched, dblock, dnet, dthreads := kvm, sched, block, net, threads
	basis, over := Basis, "lifetime"
	if per, span, ok := s.windowedInputs(vm, now, window); ok && vm.Name != "" {
		rows := windowRows(vm, per, s.cpuVendorLocked())
		dkvm, dsched, dblock, dnet, dthreads = rows.kvm, rows.sched, rows.block, rows.net, rows.threads
		carryMeasured(dkvm, dsched, dblock, kvm, sched, block)
		over = span.Round(time.Second).String()
		basis = "Over the last " + over + ". Latencies come from log2 buckets, so each can read up to 2x high. They are the QEMU process's, not the guest's."
	}

	var evidence []string
	if vm.Name != "" {
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
	missing := []string{"CPU steal", "in-guest process identity"}
	tapAttached := false
	for _, p := range s.Programs() {
		if p.Name == "tap" && p.Status == "attached" {
			tapAttached = true
		}
	}
	if !tapAttached {
		missing = append([]string{"guest tap attribution (TCX on the VM tap is not attached)"}, missing...)
	}
	return Explain{
		VM: vm, Question: "why is this VM slow?", Window: over,
		Findings: diagnose(vm.Name != "", dkvm, dsched, dthreads, dblock, dnet),
		Basis:    basis,
		Evidence: evidence,
		Missing:  missing,
		Events:   s.Recorder(name, 60*time.Second, now),
	}
}

type windowedRows struct {
	kvm     []aggregate.KVMRow
	sched   []aggregate.SchedRow
	block   []aggregate.BlockRow
	net     []aggregate.NetRow
	threads []aggregate.ThreadRow
}

// windowRows turns per-thread window counters into the same rows the API serves,
// by treating the window as if it were the whole history.
func windowRows(vm identity.VM, per map[uint32]aggregate.Counters, vendor string) windowedRows {
	syn := vm
	rows := windowedRows{
		kvm:     aggregate.KVM([]identity.VM{syn}, per, vm.Name),
		sched:   aggregate.Sched([]identity.VM{syn}, per, vm.Name),
		block:   aggregate.Block([]identity.VM{syn}, per, vm.Name),
		net:     aggregate.Net([]identity.VM{syn}, per, vm.Name),
		threads: aggregate.SchedThreads([]identity.VM{syn}, per, vm.Name),
	}
	aggregate.NameReasons(rows.kvm, vendor)
	return rows
}

// carryMeasured copies each program's Measured flag from the lifetime rows. A
// window with no activity has empty counters, which says nothing about whether
// the program is attached.
func carryMeasured(dkvm []aggregate.KVMRow, dsched []aggregate.SchedRow, dblock []aggregate.BlockRow,
	kvm []aggregate.KVMRow, sched []aggregate.SchedRow, block []aggregate.BlockRow) {
	if len(dkvm) > 0 && len(kvm) > 0 {
		dkvm[0].Measured = kvm[0].Measured
	}
	if len(dsched) > 0 && len(sched) > 0 {
		dsched[0].Measured = sched[0].Measured
	}
	if len(dblock) > 0 && len(block) > 0 {
		dblock[0].Measured = block[0].Measured
	}
}

// Export is the document a downstream consumer can take. It does not add fields
// this build did not measure.
type Export struct {
	Status   Status               `json:"status"`
	VMs      []identity.VM        `json:"vms"`
	Programs []Program            `json:"programs"`
	KVM      []aggregate.KVMRow   `json:"kvm"`
	Sched    []aggregate.SchedRow `json:"sched"`
	Block    []aggregate.BlockRow `json:"block"`
	Net      []aggregate.NetRow   `json:"net"`
	Events   []event.Event        `json:"events"`
}

func (s *State) Export() Export {
	return Export{
		Status:   s.Status(),
		VMs:      s.VMs(),
		Programs: s.Programs(),
		KVM:      s.KVM(""),
		Sched:    s.Sched(""),
		Block:    s.Block(""),
		Net:      s.Net(""),
		Events:   s.Events(""),
	}
}
