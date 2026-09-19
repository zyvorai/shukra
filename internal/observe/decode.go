package observe

import (
	"encoding/binary"
	"net"
	"strings"

	"github.com/zyvorai/shukra/internal/event"
)

// ring_event in bpf/event.h. Every field is explicitly placed there, and the C
// side asserts the size at compile time:
//
//	 0 ts_ns u64   8 pid u32   12 tgid u32   16 kind u32   20 dport u16   22 family u16
//	24 dst_be u32  28 ppid u32 32 aux_ns u64 40 comm [16]  56 dst6 [16]   = 72
const ringEventSize = 72

const (
	familyInet  = 2
	familyInet6 = 10
)

// DecodeRing turns one ring sample into an event. False means the record is
// too short or the kind is unknown. Those are counted as lost, not replayed.
func DecodeRing(b []byte) (event.Event, bool) {
	if len(b) < ringEventSize {
		return event.Event{}, false
	}
	kind := binary.LittleEndian.Uint32(b[16:20])
	var ek event.Kind
	switch kind {
	case 1:
		ek = event.KindExec
	case 2:
		ek = event.KindTCPConnect
	case 3:
		ek = event.KindTCPRetransmit
	case 4:
		ek = event.KindBlockSlow
	case 5:
		ek = event.KindSchedDelay
	case 6:
		ek = event.KindExit
	default:
		return event.Event{}, false
	}
	e := event.Event{
		Kind: ek,
		PID:  binary.LittleEndian.Uint32(b[8:12]),
		TGID: binary.LittleEndian.Uint32(b[12:16]),
		PPID: binary.LittleEndian.Uint32(b[28:32]),
		Comm: cString(b[40:56]),
	}
	if ek == event.KindTCPConnect || ek == event.KindTCPRetransmit {
		e.DPort = binary.LittleEndian.Uint16(b[20:22])
		switch binary.LittleEndian.Uint16(b[22:24]) {
		case familyInet6:
			e.Dst = net.IP(b[56:72]).String()
		case familyInet:
			if dst := binary.LittleEndian.Uint32(b[24:28]); dst != 0 {
				e.Dst = net.IPv4(byte(dst), byte(dst>>8), byte(dst>>16), byte(dst>>24)).String()
			}
		}
	}
	if ek == event.KindBlockSlow || ek == event.KindSchedDelay {
		e.LatencyNS = binary.LittleEndian.Uint64(b[32:40])
	}
	return e, true
}

func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
