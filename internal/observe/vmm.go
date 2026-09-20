package observe

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/zyvorai/shukra/internal/event"
)

// vmm event, decoded by offset. bpf/vmm.bpf.c asserts this size at compile time.
//
//	 0 ts_ns u64    8 root u32   12 pid u32   16 tid u32   20 call u32   24 dfd s32   28 flags u32
//	32 arg0 u64    40 arg1 u64   48 pathlen u16   56 comm [16]   72 path [256]                     = 328
//
// Only pathlen bytes of path are the caller's: the record is not cleared past the header, so whatever an earlier
// record left there is never read.
const (
	vmmEventSize = 328
	vmmPathOff   = 72
	vmmPathMax   = 256
	vmmCommOff   = 56

	// AtFDCWD is the dfd of an open whose path is relative to the process's working directory.
	atFDCWD = -100
)

// The calls, as bpf/vmm.bpf.c numbers them: its own numbers, so they do not depend on the architecture.
const (
	vmmOpenat           = 1
	vmmOpenat2          = 2
	vmmOpen             = 3
	vmmPtrace           = 10
	vmmProcessVMWritev  = 11
	vmmProcessVMReadv   = 12
	vmmMount            = 13
	vmmUnshare          = 14
	vmmSetns            = 15
	vmmInitModule       = 16
	vmmFinitModule      = 17
	vmmKexecLoad        = 18
	vmmKexecFileLoad    = 19
	vmmFlood            = 255
	openWrite           = 0x3 // O_WRONLY | O_RDWR
	openCreate, openTrn = 0x40, 0x200
)

var vmmCalls = map[uint32]string{
	vmmOpenat: "openat", vmmOpenat2: "openat2", vmmOpen: "open",
	vmmPtrace: "ptrace", vmmProcessVMWritev: "process_vm_writev", vmmProcessVMReadv: "process_vm_readv",
	vmmMount: "mount", vmmUnshare: "unshare", vmmSetns: "setns",
	vmmInitModule: "init_module", vmmFinitModule: "finit_module",
	vmmKexecLoad: "kexec_load", vmmKexecFileLoad: "kexec_file_load",
	vmmFlood: "flood",
}

// VMMSyscallNames is every call the tripwire reports other than an open, as the rules file names them.
func VMMSyscallNames() []string {
	return []string{"ptrace", "process_vm_writev", "process_vm_readv", "mount", "unshare", "setns", "init_module", "finit_module", "kexec_load", "kexec_file_load"}
}

var ptraceRequests = map[uint64]string{0: "TRACEME", 1: "PEEKTEXT", 2: "PEEKDATA", 4: "POKETEXT", 5: "POKEDATA", 16: "ATTACH", 17: "DETACH", 0x4206: "SEIZE"}

var cloneNamespaces = []struct {
	bit  uint64
	name string
}{{0x20000, "mount"}, {0x10000000, "user"}, {0x20000000, "pid"}, {0x40000000, "net"}, {0x2000000, "cgroup"}, {0x4000000, "uts"}, {0x8000000, "ipc"}}

// printablePath makes bytes from a process safe to put in a log, a terminal or JSON: a byte that is not a
// printable ASCII character is shown as '?'. Unlike a name, a path keeps its case: /Etc is not /etc.
func printablePath(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			out[i] = c
		} else {
			out[i] = '?'
		}
	}
	return string(out)
}

func namespaces(flags uint64) string {
	var names []string
	for _, n := range cloneNamespaces {
		if flags&n.bit != 0 {
			names = append(names, n.name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ")
}

// vmmDetail reads a call's arguments in words.
func vmmDetail(call uint32, a0, a1 uint64) string {
	switch call {
	case vmmPtrace:
		req := fmt.Sprint(a0)
		if n, ok := ptraceRequests[a0]; ok {
			req = fmt.Sprintf("%d (%s)", a0, n)
		}
		return fmt.Sprintf("request %s on pid %d", req, int32(a1))
	case vmmProcessVMWritev:
		return fmt.Sprintf("writes the memory of pid %d", int32(a0))
	case vmmProcessVMReadv:
		return fmt.Sprintf("reads the memory of pid %d", int32(a0))
	case vmmMount:
		return fmt.Sprintf("flags %#x", a0)
	case vmmUnshare:
		if n := namespaces(a0); n != "" {
			return "new " + n + " namespace"
		}
		return "no namespace flag"
	case vmmSetns:
		return fmt.Sprintf("into the namespace of fd %d, type %#x", int32(a0), a1)
	case vmmFinitModule:
		return fmt.Sprintf("module fd %d, flags %#x", int32(a0), a1)
	}
	return ""
}

// decodeVMM turns one vmm_events sample into an event. The VM is filled in later, from the root, by whoever
// knows which VM that process is.
func decodeVMM(b []byte, _ func(uint32) string) (event.Event, bool) {
	if len(b) < vmmEventSize {
		return event.Event{}, false
	}
	call := binary.LittleEndian.Uint32(b[20:24])
	name, known := vmmCalls[call]
	if !known {
		return event.Event{}, false
	}
	comm := b[vmmCommOff : vmmCommOff+16]
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	e := event.Event{
		TGID:    binary.LittleEndian.Uint32(b[8:12]),
		PID:     binary.LittleEndian.Uint32(b[12:16]),
		Comm:    printablePath(comm[:n]),
		Syscall: name,
	}
	a0, a1 := binary.LittleEndian.Uint64(b[32:40]), binary.LittleEndian.Uint64(b[40:48])
	switch call {
	case vmmOpenat, vmmOpenat2, vmmOpen:
		e.Kind = event.KindVMMOpen
		flags := binary.LittleEndian.Uint32(b[28:32])
		e.Write = call != vmmOpenat2 && (flags&openWrite != 0 || flags&openCreate != 0 || flags&openTrn != 0)
		pl := int(binary.LittleEndian.Uint16(b[48:50]))
		if pl > vmmPathMax {
			pl = vmmPathMax
		}
		path := b[vmmPathOff : vmmPathOff+pl]
		if k := indexNUL(path); k >= 0 {
			path = path[:k]
		}
		e.Path = printablePath(path)
		if int32(binary.LittleEndian.Uint32(b[24:28])) != atFDCWD && !strings.HasPrefix(e.Path, "/") && e.Path != "" {
			e.Detail = fmt.Sprintf("relative to fd %d", int32(binary.LittleEndian.Uint32(b[24:28])))
		}
	case vmmFlood:
		e.Kind = event.KindVMMCall
		e.Count = a0
	default:
		e.Kind = event.KindVMMCall
		e.Detail = vmmDetail(call, a0, a1)
	}
	return e, true
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
