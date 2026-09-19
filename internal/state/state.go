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
	VM          string `json:"vm"`
	Enforcement string `json:"enforcement"`
	Applied     bool   `json:"applied"`
	Reason      string `json:"reason"`
	Audit       Audit  `json:"audit"`
}

// Explain is the evidence available for one VM, plus what this build cannot say.
type Explain struct {
	VM       identity.VM   `json:"vm"`
	Question string        `json:"question"`
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
	mu         sync.RWMutex
	started    time.Time
	hostname   string
	vms        []identity.VM
	programs   []Program
	byPID      map[uint32]aggregate.Counters
	detections []event.Event
	events     []event.Event
	isolations []Isolation
	rec        *recorder.Recorder
}

func New(hostname string) *State {
	return &State{
		started:  time.Now().UTC(),
		hostname: hostname,
		byPID:    map[uint32]aggregate.Counters{},
		rec:      recorder.New(recorder.DefaultCap),
		programs: []Program{
			{Name: "kvm", Status: "detached", Detail: "not attached yet"},
			{Name: "sched", Status: "detached", Detail: "not attached yet"},
			{Name: "block", Status: "detached", Detail: "not attached yet"},
			{Name: "net", Status: "detached", Detail: "not attached yet"},
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

func (s *State) SetPrograms(p []Program) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.programs = append([]Program(nil), p...)
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
}

func (s *State) AddEvent(e event.Event) {
	event.Normalize(&e)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	if len(s.events) > 2048 {
		s.events = append([]event.Event(nil), s.events[len(s.events)-2048:]...)
	}
	if e.Kind == event.KindDetection {
		s.detections = append(s.detections, e)
	}
	s.rec.Add(e)
}

func (s *State) Events(vm string) []event.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []event.Event
	for _, e := range s.events {
		if vm == "" || e.VM.Name == vm {
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

func (s *State) Recorder(vm string, window time.Duration, now time.Time) []event.Event {
	return s.rec.Window(vm, window, now)
}

func (s *State) Isolate(vm, actor string) Isolation {
	rec := Isolation{
		VM:          vm,
		Enforcement: "not_attached",
		Applied:     false,
		Reason:      "TC/TCX tap enforcement is not in this build. No program was attached.",
		Audit: Audit{
			TS: time.Now().UTC(), Actor: actor, Action: "isolate", VM: vm, Result: "recorded_only",
		},
	}
	s.mu.Lock()
	s.isolations = append(s.isolations, rec)
	s.mu.Unlock()
	return rec
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
	return Status{
		Version: version.Version, Product: version.Product, Tagline: version.Tagline,
		Mode: "observe", Datapath: "tracepoint-kprobe", Healthy: true,
		VMs: len(s.vms), ProgramsAttached: att, ProgramsTotal: len(s.programs),
		Detections: len(s.detections),
		Summary:    "observe: host traces only, guest tap attribution not attached",
	}
}

func (s *State) KVM(vm string) []aggregate.KVMRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return aggregate.KVM(s.vms, s.byPID, vm)
}

func (s *State) Sched(vm string) []aggregate.SchedRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return aggregate.Sched(s.vms, s.byPID, vm)
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
	for _, e := range s.events {
		if e.Kind != event.KindTCPConnect {
			continue
		}
		name := e.VM.Name
		if name == "" {
			name = aggregate.Host
		}
		if vm != "" && name != vm {
			continue
		}
		counts[name]++
	}
	seen := map[string]bool{}
	for i := range rows {
		rows[i].Connects += counts[rows[i].VM]
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

func (s *State) Explain(name string, now time.Time) Explain {
	vm, _ := s.FindVM(name)
	kvm := s.KVM(name)
	sched := s.Sched(name)
	block := s.Block(name)
	net := s.Net(name)
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
		if block[0].ReadP99Ns >= aggregate.SlowBlockNS || block[0].WriteP99Ns >= aggregate.SlowBlockNS {
			evidence = append(evidence, "Block p99 is at least 10ms on the QEMU iothread.")
		}
	}
	if len(sched) > 0 && sched[0].Measured && sched[0].WakeupCount > 0 && sched[0].WakeupDelayNs/sched[0].WakeupCount >= aggregate.SlowWakeupNS {
		evidence = append(evidence, "Mean wakeup delay is at least 20ms.")
	}
	if len(net) > 0 && (net[0].Connects > 0 || net[0].Retransmits > 0) {
		evidence = append(evidence, "TCP connects are from the QEMU process. They are not guest flows.")
	}
	return Explain{
		VM: vm, Question: "why is this VM slow?",
		Evidence: evidence,
		Missing: []string{
			"guest tap attribution (TC/TCX on the VM tap is not attached)",
			"CPU steal",
			"in-guest process identity",
		},
		Events: s.Recorder(name, 60*time.Second, now),
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
