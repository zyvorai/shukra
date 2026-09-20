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
	KindGuestConnect  Kind = "guest_connect"
	KindGuestFlow     Kind = "guest_flow"
	// KindGuestInbound is a TCP SYN sent TO a guest: someone connecting in. Src is the peer, Dst the guest.
	KindGuestInbound Kind = "guest_inbound"
	// KindGuestDNS is a DNS query the guest sent, with the name it asked for. It is a first question over
	// UDP port 53 seen on the tap, so a resolver the guest reaches over TLS or HTTPS is not seen.
	KindGuestDNS Kind = "guest_dns"
	// KindGuestTLS is a TLS ClientHello the guest sent, with the server name it asked for (SNI). It is the
	// first segment of a hello seen on the tap, so a name hidden by Encrypted Client Hello, or a hello that
	// does not fit the copy, is not seen in full, and a protocol that is not TLS over TCP (QUIC) is not seen.
	KindGuestTLS Kind = "guest_tls"
	// KindVMMOpen is a file opened by a VMM process (QEMU) or by something it started. A VMM in steady state
	// opens nothing, so any is worth a look; Path is as the caller gave it.
	KindVMMOpen Kind = "vmm_file_open"
	// KindVMMCall is a call a VMM has no business making: ptrace, mount, unshare, setns, a module or a kexec
	// load. Syscall names it. A VMM that reports more than it is allowed in a second is a call named "flood".
	KindVMMCall Kind = "vmm_syscall"
)

const (
	AttributionQEMU         = "qemu-process"
	AttributionUnattributed = "unattributed"
	// AttributionGuestTap marks an event seen on a VM's tap interface. It is the
	// only attribution under which an event is guest_attributed.
	AttributionGuestTap = "guest-tap"
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
	PPID uint32 `json:"ppid,omitempty"`
	Comm string `json:"comm,omitempty"`
	Dst  string `json:"dst,omitempty"`
	// Src, Iface and Blocked are set on events seen on a VM tap. Iface is the tap
	// name, and Blocked says isolation dropped the connect attempt.
	Src string `json:"src,omitempty"`
	// Proto is "tcp" or "udp" on events seen on a tap.
	Proto   string `json:"proto,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Blocked bool   `json:"blocked,omitempty"`
	DPort   uint16 `json:"dport,omitempty"`
	Message string `json:"message,omitempty"`
	// DNSName and QType are set on guest_dns events. The name is lower-cased, and a name that did not fit is
	// cut short and says so in DNSTruncated.
	DNSName      string `json:"dns_name,omitempty"`
	QType        string `json:"qtype,omitempty"`
	DNSTruncated bool   `json:"dns_truncated,omitempty"`
	// Policy is set on a guest_connect or guest_flow that the VM's egress policy judged to be outside it:
	// "audit" when it would have been dropped (and was not), "enforce" when it was. Blocked is also set in the
	// second case.
	Policy string `json:"policy,omitempty"`
	// Syscall, Path, Write, Detail and Count are set on vmm_file_open and vmm_syscall events. Comm is the process
	// that made the call and PID is that process; TGID is the VMM it is, or descends from. Path is as it was
	// given, made printable. Write says an open asked to write. Detail reads the call's arguments. Count is how
	// many calls a flooding VMM made that were not reported.
	Syscall string `json:"syscall,omitempty"`
	Path    string `json:"path,omitempty"`
	Write   bool   `json:"write,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Count   uint64 `json:"count,omitempty"`
	// SNI, ALPN, TLSVersion, JA3, ECH and TLSTruncated are set on guest_tls events. SNI is lower-cased and
	// made printable. TLSVersion is the highest version the client offered. JA3 is only set when the whole
	// hello was seen. ECH says the hello carries Encrypted Client Hello, so SNI is the outer name at most.
	SNI          string `json:"sni,omitempty"`
	ALPN         string `json:"alpn,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	JA3          string `json:"ja3,omitempty"`
	ECH          bool   `json:"ech,omitempty"`
	TLSTruncated bool   `json:"tls_truncated,omitempty"`
	// Rule names the detection rule that fired, so a consumer can route on it
	// without parsing Message.
	Rule      string `json:"rule,omitempty"`
	Severity  string `json:"severity,omitempty"`
	LatencyNS uint64 `json:"latency_ns,omitempty"`
}

// Normalize forces the product name and the guest-attribution boundary. An event
// is guest_attributed only when it was seen on a VM's tap and names that VM.
// Everything else, including anything read back from a file, is the QEMU process
// or unattributed.
func Normalize(e *Event) {
	e.Product = "shukra"
	if e.Attribution == AttributionGuestTap && e.VM.Name != "" {
		e.GuestAttributed = true
		return
	}
	e.GuestAttributed = false
	if e.VM.Name != "" {
		e.Attribution = AttributionQEMU
		return
	}
	if e.Attribution == "" || e.Attribution == AttributionGuestTap {
		e.Attribution = AttributionUnattributed
	}
}
