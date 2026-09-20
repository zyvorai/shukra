package observe

import (
	"crypto/md5" // #nosec G501 -- JA3 is defined as an MD5 of a description; it is a label, not a security control
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"github.com/zyvorai/shukra/internal/event"
)

// tls event, decoded by offset. bpf/tap.bpf.c asserts this size at compile time.
//
//	 0 ts_ns u64   8 ifindex u32  12 family u8  13 flags u8  14 rawlen u16
//	16 sport u16  18 dport u16    24 src [16]   40 dst [16]   56 raw [1504] = 1560
//
// raw is the TCP payload of the guest's segment, from the TLS record header. Only rawlen bytes of it are the
// packet's: the rest of the record is not looked at.
const (
	tlsEventSize = 1560
	tlsRawOffset = 56
	tlsRawMax    = 1504

	tlsFlagBlocked = 1 // isolation dropped the segment

	extServerName     = 0
	extSupportedGroup = 10
	extPointFormats   = 11
	extALPN           = 16
	extSupportedVers  = 43
	extECH            = 0xfe0d

	maxSNI   = 253
	maxALPN  = 64
	maxHello = 1 << 14 // a TLS record holds at most 16 KiB, so a hello that says it is longer is not one
)

// clientHello is what a ClientHello says about its sender. Everything is derived from bytes a guest chose,
// so every string is made printable before it leaves this file.
type clientHello struct {
	SNI       string
	ALPN      string
	Version   string // the highest version offered: "1.3", "1.2", ..., or "" when it could not be read
	JA3       string // only when the whole hello was seen
	ECH       bool   // Encrypted Client Hello: the name above, if any, is the outer one
	Truncated bool   // the hello did not end inside what was copied
}

// isGrease says a value is one of the reserved GREASE values (0x0a0a, 0x1a1a ... 0xfafa) that clients add so
// that servers cannot depend on the list they see. A fingerprint leaves them out.
func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// tlsVersionName names a protocol version, or "" for one that is not a version.
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	case 0x0300:
		return "SSL3"
	}
	return ""
}

// printable turns bytes from a guest into text that is safe to put in a log, a terminal or JSON: lower case,
// and any byte that is not a printable ASCII character shown as '?'.
func printable(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			out[i] = c + 32
		case c > 0x20 && c < 0x7f:
			out[i] = c
		default:
			out[i] = '?'
		}
	}
	return string(out)
}

// reader walks a byte slice and remembers when it ran off the end.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func (r *reader) u24() int {
	if v := r.take(3); v != nil {
		return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
	}
	return 0
}

// parseClientHello reads a ClientHello that starts at the TLS record header. ok is false for something that
// is not one. A hello that ends before its extensions do is still read as far as it goes, and says so in
// Truncated: the name can be there even when the fingerprint cannot.
func parseClientHello(raw []byte) (h clientHello, ok bool) {
	// The kernel program has checked these bytes too; a decoder that trusted it would be trusting a sample.
	// The top byte of the handshake length is covered by the limit on the length below.
	if len(raw) < 6 || raw[0] != 0x16 || raw[1] != 3 || raw[2] > 4 || raw[5] != 1 {
		return h, false
	}
	// The handshake message starts after the 5-byte record header: type, a 24-bit length, then the body.
	r := &reader{b: raw[5:]}
	r.u8()
	want := r.u24()
	if r.bad || want > maxHello {
		return h, false
	}
	body := r.b
	if want > len(body) {
		h.Truncated = true
	} else {
		body = body[:want]
	}
	b := &reader{b: body}
	legacy := b.u16()
	b.take(32) // random
	sid := b.u8()
	b.take(sid)
	nCipher := b.u16()
	ciphers := b.take(nCipher)
	comp := b.u8()
	b.take(comp)
	if b.bad {
		h.Truncated = true
		return h, true // it is a hello, cut off before its extensions
	}

	var cs, ex, groups, formats []string
	for i := 0; i+1 < len(ciphers); i += 2 {
		if v := binary.BigEndian.Uint16(ciphers[i:]); !isGrease(v) {
			cs = append(cs, strconv.Itoa(int(v)))
		}
	}

	if len(b.b) < 2 {
		// No extensions at all: a valid, old-style hello.
		if !h.Truncated {
			h.Version = tlsVersionName(uint16(legacy))
			h.JA3 = ja3(legacy, cs, ex, groups, formats)
		}
		return h, true
	}
	extLen := b.u16()
	exts := b.b
	if extLen > len(exts) {
		h.Truncated = true
	} else {
		exts = exts[:extLen]
	}
	best := uint16(0)
	e := &reader{b: exts}
	for len(e.b) >= 4 {
		typ := e.u16()
		n := e.u16()
		data := e.b
		if n > len(data) {
			// The extension runs past what was copied. What is there of it is not a whole name or list, so
			// none of it is used: a half name would look like a different site.
			h.Truncated = true
			e.b = nil
			break
		} else {
			data = data[:n]
			e.b = e.b[n:]
		}
		if !isGrease(uint16(typ)) {
			ex = append(ex, strconv.Itoa(typ))
		}
		switch typ {
		case extServerName:
			h.SNI = serverName(data)
		case extALPN:
			h.ALPN = alpn(data)
		case extSupportedVers:
			for i := 1; i+1 < len(data); i += 2 {
				v := binary.BigEndian.Uint16(data[i:])
				if tlsVersionName(v) != "" && v > best { // GREASE is not a known version
					best = v
				}
			}
		case extSupportedGroup:
			for i := 2; i+1 < len(data); i += 2 {
				if v := binary.BigEndian.Uint16(data[i:]); !isGrease(v) {
					groups = append(groups, strconv.Itoa(int(v)))
				}
			}
		case extPointFormats:
			for i := 1; i < len(data); i++ {
				formats = append(formats, strconv.Itoa(int(data[i])))
			}
		case extECH:
			h.ECH = true
		}
	}
	if len(e.b) > 0 && len(e.b) < 4 {
		h.Truncated = true // the last extension header was cut
	}
	if best != 0 {
		h.Version = tlsVersionName(best)
	} else {
		h.Version = tlsVersionName(uint16(legacy))
	}
	if !h.Truncated {
		h.JA3 = ja3(legacy, cs, ex, groups, formats)
	}
	return h, true
}

// serverName reads the host name of a server_name extension.
func serverName(data []byte) string {
	r := &reader{b: data}
	list := r.u16()
	l := &reader{b: r.take(min(list, len(r.b)))}
	for !l.bad && len(l.b) >= 3 {
		typ := l.u8()
		n := l.u16()
		name := l.take(min(n, len(l.b)))
		if typ == 0 { // host_name
			return strings.Trim(printable(name, maxSNI), ".")
		}
	}
	return ""
}

// alpn reads the protocol names of an ALPN extension as a comma-separated list.
func alpn(data []byte) string {
	r := &reader{b: data}
	list := r.u16()
	l := &reader{b: r.take(min(list, len(r.b)))}
	var names []string
	for !l.bad && len(l.b) >= 1 && len(names) < 8 {
		n := l.u8()
		p := l.take(min(n, len(l.b)))
		if len(p) > 0 {
			names = append(names, printable(p, 32))
		}
	}
	s := strings.Join(names, ",")
	if len(s) > maxALPN {
		s = s[:maxALPN]
	}
	return s
}

// ja3 is the JA3 fingerprint: an MD5 of the version, the ciphers, the extensions, the groups and the point
// formats the client offered, each as decimal numbers in the order it sent them, GREASE left out. It says
// what kind of client library made the hello, not who the client is. A client that randomises the order of
// its extensions (a current browser) has a different one each time.
func ja3(version int, ciphers, exts, groups, formats []string) string {
	s := strconv.Itoa(version) + "," + strings.Join(ciphers, "-") + "," + strings.Join(exts, "-") + "," +
		strings.Join(groups, "-") + "," + strings.Join(formats, "-")
	sum := md5.Sum([]byte(s)) // #nosec G401 -- see the import
	return hex.EncodeToString(sum[:])
}

// decodeTLS turns one tap_tls ring sample into a guest_tls event. The VM is filled in later, from the
// interface name, by whoever knows which VM owns that tap.
func decodeTLS(b []byte, name func(ifindex uint32) string) (event.Event, bool) {
	if len(b) < tlsEventSize {
		return event.Event{}, false
	}
	e := event.Event{
		Kind:    event.KindGuestTLS,
		Proto:   "tcp",
		Iface:   name(binary.LittleEndian.Uint32(b[8:12])),
		DPort:   binary.LittleEndian.Uint16(b[18:20]),
		Blocked: b[13]&tlsFlagBlocked != 0,
	}
	switch b[12] {
	case 2:
		e.Src, e.Dst = net.IP(b[24:28]).String(), net.IP(b[40:44]).String()
	case 10:
		e.Src, e.Dst = net.IP(b[24:40]).String(), net.IP(b[40:56]).String()
	default:
		return event.Event{}, false
	}
	if e.Iface == "" {
		return event.Event{}, false // a tap we no longer track
	}
	n := int(binary.LittleEndian.Uint16(b[14:16]))
	if n > tlsRawMax {
		n = tlsRawMax
	}
	h, ok := parseClientHello(b[tlsRawOffset : tlsRawOffset+n])
	if !ok {
		return event.Event{}, false
	}
	e.SNI, e.ALPN, e.TLSVersion, e.JA3, e.ECH, e.TLSTruncated = h.SNI, h.ALPN, h.Version, h.JA3, h.ECH, h.Truncated
	return e, true
}
