// Package event is the stable JSON shape PacketWolf can consume later.
package event

import "time"

type Kind string

const (
	KindExec          Kind = "exec"
	KindTCPConnect    Kind = "tcp_connect"
	KindTCPRetransmit Kind = "tcp_retransmit"
	KindBlockSlow     Kind = "block_slow"
	KindSchedDelay    Kind = "sched_delay"
	KindExit          Kind = "exit"
	KindDetection     Kind = "detection"
	KindVMStart       Kind = "vm_start"
	KindVMStop        Kind = "vm_stop"
)

const (
	AttributionQEMU         = "qemu-process"
	AttributionUnattributed = "unattributed"
)

// VM is the identity attached to an event. Empty name means the PID was not a QEMU thread.
type VM struct {
	Name    string `json:"name,omitempty"`
	UUID    string `json:"uuid,omitempty"`
	Runtime string `json:"runtime,omitempty"`
}

// Event is one discrete observation. Hot counters never use this path.
type Event struct {
	// Seq is assigned by the daemon when it stores the event. It only grows, so a
	// client can ask for everything after the last Seq it saw.
	Seq             uint64    `json:"seq,omitempty"`
	Product         string    `json:"product"`
	Kind            Kind      `json:"kind"`
	TS              time.Time `json:"ts"`
	VM              VM        `json:"vm"`
	Attribution     string    `json:"attribution"`
	GuestAttributed bool      `json:"guest_attributed"`
	PID             uint32    `json:"pid,omitempty"`
	TGID            uint32    `json:"tgid,omitempty"`
	// PPID is the tgid of the parent process, read by the kernel program for exec
	// and exit events. It lets an event be joined to a VM after the process is gone.
	PPID    uint32 `json:"ppid,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Dst     string `json:"dst,omitempty"`
	DPort   uint16 `json:"dport,omitempty"`
	Message string `json:"message,omitempty"`
	// Rule names the detection rule that fired, so a consumer can route on it
	// without parsing Message.
	Rule      string `json:"rule,omitempty"`
	Severity  string `json:"severity,omitempty"`
	LatencyNS uint64 `json:"latency_ns,omitempty"`
}

// Normalize forces the product name and the guest-attribution boundary.
func Normalize(e *Event) {
	e.Product = "shukra"
	e.GuestAttributed = false
	if e.VM.Name != "" {
		e.Attribution = AttributionQEMU
		return
	}
	if e.Attribution == "" {
		e.Attribution = AttributionUnattributed
	}
}
