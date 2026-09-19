package observe

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/zyvorai/shukra/internal/event"
)

// dns event, decoded by offset. bpf/tap.bpf.c asserts this size at compile time.
//
//	 0 ts_ns u64   8 ifindex u32  12 family u8  13 flags u8  14 rawlen u16
//	16 src [16]   32 dst [16]     48 raw [128]                              = 176
//
// raw is the question section in wire format: length-prefixed labels, a zero byte, then the type and class.
const (
	dnsEventSize = 176
	dnsRawOffset = 48
	dnsRawMax    = 128

	dnsFlagBlocked    = 1 // isolation dropped the query
	dnsFlagUnfinished = 2 // the name did not end inside raw
	maxDNSName        = 253
)

var qtypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
	35: "NAPTR", 43: "DS", 48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

func qtypeName(t uint16) string {
	if n, ok := qtypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// parseQName reads the first question out of raw. The name is lower-cased and joined with dots, and a byte
// that is not a printable character is shown as '?', so a name from a hostile guest cannot smuggle a line
// break or an escape sequence into a log, a terminal or a JSON consumer. done says the name ended and the
// type was present; when it did not, the labels read so far are returned and the caller marks the name as
// cut short. ok is false for something that is not a plain first question: a label longer than 63 bytes is
// a compression pointer or an extension, which a first question does not use.
func parseQName(raw []byte) (name string, qtype uint16, done, ok bool) {
	var sb strings.Builder
	i := 0
	for {
		if i >= len(raw) {
			return sb.String(), 0, false, true
		}
		n := int(raw[i])
		if n == 0 {
			i++
			break
		}
		if n > 63 {
			return "", 0, false, false
		}
		if i+1+n > len(raw) {
			// The label runs past what was copied: keep what there is.
			writeLabel(&sb, raw[i+1:])
			return sb.String(), 0, false, true
		}
		writeLabel(&sb, raw[i+1:i+1+n])
		i += 1 + n
		if sb.Len() > maxDNSName {
			return sb.String()[:maxDNSName], 0, false, true
		}
	}
	if i+2 > len(raw) {
		return sb.String(), 0, false, true
	}
	return sb.String(), binary.BigEndian.Uint16(raw[i : i+2]), true, true
}

func writeLabel(sb *strings.Builder, label []byte) {
	if sb.Len() > 0 {
		sb.WriteByte('.')
	}
	for _, c := range label {
		switch {
		case c >= 'A' && c <= 'Z':
			sb.WriteByte(c + 32)
		case c > 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('?')
		}
	}
}

// decodeDNS turns one tap_dns ring sample into a guest_dns event. The VM is filled in later, from the
// interface name, by whoever knows which VM owns that tap.
func decodeDNS(b []byte, name func(ifindex uint32) string) (event.Event, bool) {
	if len(b) < dnsEventSize {
		return event.Event{}, false
	}
	e := event.Event{
		Kind:    event.KindGuestDNS,
		Proto:   "udp",
		DPort:   53,
		Iface:   name(binary.LittleEndian.Uint32(b[8:12])),
		Blocked: b[13]&dnsFlagBlocked != 0,
	}
	switch b[12] {
	case 2:
		e.Src, e.Dst = net.IP(b[16:20]).String(), net.IP(b[32:36]).String()
	case 10:
		e.Src, e.Dst = net.IP(b[16:32]).String(), net.IP(b[32:48]).String()
	default:
		return event.Event{}, false
	}
	if e.Iface == "" {
		return event.Event{}, false // a tap we no longer track
	}
	n := int(binary.LittleEndian.Uint16(b[14:16]))
	if n > dnsRawMax {
		n = dnsRawMax
	}
	qname, qtype, done, ok := parseQName(b[dnsRawOffset : dnsRawOffset+n])
	if !ok {
		return event.Event{}, false
	}
	if qname == "" {
		qname = "." // the root
	}
	e.DNSName = qname
	if done {
		e.QType = qtypeName(qtype)
	} else {
		e.DNSTruncated = true
	}
	return e, true
}
