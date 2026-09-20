package observe

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

// The hellos in testdata were captured from real clients (Python's ssl, OpenSSL 3.6 and curl), and their JA3
// was worked out by a separate implementation, in Python, from the same bytes.
type realHello struct {
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	JA3  string `json:"ja3"`
	Hex  string `json:"hex"`
	Len  int    `json:"len"`
}

func realHellos(t *testing.T) map[string]realHello {
	t.Helper()
	b, err := os.ReadFile("testdata/tls_hellos.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]realHello
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (r realHello) bytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(r.Hex)
	if err != nil || len(b) != r.Len {
		t.Fatalf("fixture: %v %d", err, len(b))
	}
	return b
}

func TestRealHellosGiveTheNameTheProtocolsAndTheSameFingerprintAsAnIndependentImplementation(t *testing.T) {
	for name, r := range realHellos(t) {
		h, ok := parseClientHello(r.bytes(t))
		if !ok || h.Truncated {
			t.Fatalf("%s: ok=%v %+v", name, ok, h)
		}
		if h.SNI != r.SNI || h.ALPN != r.ALPN || h.JA3 != r.JA3 || h.Version != "1.3" || h.ECH {
			t.Fatalf("%s: got %+v, want sni=%q alpn=%q ja3=%s", name, h, r.SNI, r.ALPN, r.JA3)
		}
	}
}

func TestAHelloCutShortKeepsTheNameButHasNoFingerprint(t *testing.T) {
	r := realHellos(t)["python_h2"]
	full := r.bytes(t)
	// The copy is a bounded prefix of the first segment.
	h, ok := parseClientHello(full[:tlsRawMax])
	if !ok || !h.Truncated || h.SNI != r.SNI || h.JA3 != "" {
		t.Fatalf("a hello longer than the copy: %v %+v", ok, h)
	}
	// Cut right after the server name extension: the name is there, what comes later is not.
	h, ok = parseClientHello(full[:160])
	if !ok || !h.Truncated || h.SNI != r.SNI || h.ALPN != "" || h.JA3 != "" {
		t.Fatalf("cut at 160: %v %+v", ok, h)
	}
	// Cut later, after the protocol list too.
	h, ok = parseClientHello(full[:300])
	if !ok || !h.Truncated || h.SNI != r.SNI || h.ALPN != r.ALPN || h.JA3 != "" {
		t.Fatalf("cut at 300: %v %+v", ok, h)
	}
	// Cut in the middle of the name: what was there is not a name, and is not reported as a complete one.
	h, ok = parseClientHello(full[:135])
	if !ok || !h.Truncated || h.JA3 != "" || h.SNI != "" {
		t.Fatalf("cut inside the name: %v %+v", ok, h)
	}
}

func TestNoPrefixOfAHelloPanicsAndOnlyTheWholeOneHasAFingerprint(t *testing.T) {
	for name, r := range realHellos(t) {
		full := r.bytes(t)
		for n := 0; n <= len(full); n++ {
			h, ok := parseClientHello(full[:n])
			if n < 6 && ok {
				t.Fatalf("%s: %d bytes cannot be a hello", name, n)
			}
			if ok && n < len(full) && (!h.Truncated || h.JA3 != "") {
				t.Fatalf("%s: %d of %d bytes claims to be whole: %+v", name, n, len(full), h)
			}
			if n == len(full) && (!ok || h.Truncated || h.JA3 != r.JA3) {
				t.Fatalf("%s: the whole hello: %v %+v", name, ok, h)
			}
		}
	}
}

func TestWhatIsNotAClientHelloIsRefused(t *testing.T) {
	good := realHellos(t)["curl"].bytes(t)
	edit := func(i int, v byte) []byte {
		b := append([]byte(nil), good...)
		b[i] = v
		return b
	}
	for name, b := range map[string][]byte{
		"empty":                   nil,
		"five bytes":              good[:5],
		"application data":        edit(0, 0x17),
		"alert":                   edit(0, 0x15),
		"not version 3":           edit(1, 2),
		"a ServerHello":           edit(5, 2),
		"record version 3.5":      edit(2, 5),
		"a length above 64 KiB":   edit(6, 1),
		"a length above a record": func() []byte { b := edit(7, 0x40); b[8] = 1; return b }(),
		"plain http":              []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	} {
		if _, ok := parseClientHello(b); ok {
			t.Fatalf("%s was taken for a ClientHello", name)
		}
	}
}

// ext and hello build a ClientHello by hand, so a test can say exactly what is in it.
func ext(typ uint16, data ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func u16s(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint16(b, x)
	}
	return b
}

func hello(legacy uint16, ciphers []uint16, exts ...[]byte) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, legacy)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // no session id
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(ciphers)))
	body = append(body, u16s(ciphers...)...)
	body = append(body, 1, 0) // one compression method: null
	if exts != nil {
		var all []byte
		for _, e := range exts {
			all = append(all, e...)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(all)))
		body = append(body, all...)
	}
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sni(name string) []byte {
	l := len(name)
	d := []byte{byte((l + 3) >> 8), byte(l + 3), 0, byte(l >> 8), byte(l)}
	return ext(0, append(d, name...)...)
}

func TestGreaseIsLeftOutOfTheFingerprintAndOfTheVersion(t *testing.T) {
	b := hello(0x0303, []uint16{0x0a0a, 4865, 4866},
		ext(0x1a1a),
		sni("Example.COM"),
		ext(10, append([]byte{0, 6}, u16s(0x2a2a, 29, 23)...)...),
		ext(11, 1, 0),
		ext(43, 6, 0x3a, 0x3a, 3, 4, 3, 3),
		ext(16, 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'),
		ext(0xfe0d, 1, 2, 3),
	)
	h, ok := parseClientHello(b)
	if !ok || h.Truncated {
		t.Fatalf("%v %+v", ok, h)
	}
	sum := md5.Sum([]byte("771,4865-4866,0-10-11-43-16-65037,29-23,0"))
	want := hex.EncodeToString(sum[:])
	if h.JA3 != want {
		t.Fatalf("JA3 %s, want %s", h.JA3, want)
	}
	if h.SNI != "example.com" || h.ALPN != "h2,http/1.1" || h.Version != "1.3" || !h.ECH {
		t.Fatalf("%+v", h)
	}
}

func TestTheVersionIsTheHighestOfferedAndTheLegacyOneWhenThereIsNoList(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		want string
	}{
		{"1.2 offered after 1.3", hello(0x0303, []uint16{1}, ext(43, 4, 3, 3, 3, 4)), "1.3"},
		{"only 1.2 offered", hello(0x0303, []uint16{1}, ext(43, 2, 3, 3)), "1.2"},
		{"no list: the legacy field", hello(0x0303, []uint16{1}, sni("a.b")), "1.2"},
		{"no extensions at all", hello(0x0301, []uint16{1}), "1.0"},
		{"a version nobody knows", hello(0x0399, []uint16{1}, sni("a.b")), ""},
	} {
		h, ok := parseClientHello(tc.b)
		if !ok || h.Version != tc.want {
			t.Fatalf("%s: %v %+v, want %q", tc.name, ok, h, tc.want)
		}
	}
}

func TestAHelloWithNoExtensionsStillHasAFingerprint(t *testing.T) {
	h, ok := parseClientHello(hello(0x0301, []uint16{47, 53}))
	sum := md5.Sum([]byte("769,47-53,,,"))
	if !ok || h.Truncated || h.SNI != "" || h.JA3 != hex.EncodeToString(sum[:]) {
		t.Fatalf("%v %+v", ok, h)
	}
}

func TestANameFromAGuestIsMadePrintableAndBounded(t *testing.T) {
	long := strings.Repeat("a", 400)
	for name, tc := range map[string]struct{ in, want string }{
		"upper case":      {"Pool.Example.ORG", "pool.example.org"},
		"escape and nl":   {"a\x1b[31m.b\nc", "a?[31m.b?c"},
		"nul and high":    {"a\x00\xffb", "a??b"},
		"trailing dot":    {"example.com.", "example.com"},
		"a space":         {"a b", "a?b"},
		"longer than 253": {long, long[:maxSNI]},
	} {
		h, ok := parseClientHello(hello(0x0303, []uint16{1}, sni(tc.in)))
		if !ok || h.SNI != tc.want {
			t.Fatalf("%s: %v %q, want %q", name, ok, h.SNI, tc.want)
		}
	}
}

func TestOnlyAHostNameIsTakenForTheServerName(t *testing.T) {
	// name type 1 is not a host name.
	d := []byte{0, 8, 1, 0, 5, 'a', 'b', 'c', 'd', 'e'}
	h, ok := parseClientHello(hello(0x0303, []uint16{1}, ext(0, d...)))
	if !ok || h.SNI != "" {
		t.Fatalf("%v %q", ok, h.SNI)
	}
	// a second entry that is a host name.
	d = []byte{0, 13, 1, 0, 1, 'x', 0, 0, 5, 'h', 'o', 's', 't', '1'}
	h, ok = parseClientHello(hello(0x0303, []uint16{1}, ext(0, d...)))
	if !ok || h.SNI != "host1" {
		t.Fatalf("%v %q", ok, h.SNI)
	}
}

func TestALPNIsBoundedAndPrintable(t *testing.T) {
	var d []byte
	for i := 0; i < 20; i++ {
		d = append(d, 2, 'h', byte('a'+i))
	}
	d = append([]byte{byte(len(d) >> 8), byte(len(d))}, d...)
	h, ok := parseClientHello(hello(0x0303, []uint16{1}, ext(16, d...)))
	if !ok || strings.Count(h.ALPN, ",") != 7 || len(h.ALPN) > maxALPN {
		t.Fatalf("at most 8 protocols: %q", h.ALPN)
	}
	h, _ = parseClientHello(hello(0x0303, []uint16{1}, ext(16, 0, 4, 3, 'A', 0x1b, 'z')))
	if h.ALPN != "a?z" {
		t.Fatalf("%q", h.ALPN)
	}
}

func TestLengthsThatLieDoNotHangOrPanicAndMarkTheHelloTruncated(t *testing.T) {
	good := hello(0x0303, []uint16{1, 2}, sni("example.com"), ext(43, 2, 3, 4))
	for name, mutate := range map[string]func(b []byte){
		"handshake length too big": func(b []byte) { b[6], b[7], b[8] = 0xff, 0xff, 0xff },
		"handshake length zero":    func(b []byte) { b[6], b[7], b[8] = 0, 0, 0 },
		"cipher list too long":     func(b []byte) { b[5+4+2+32+1] = 0xff },
		"extension too long":       func(b []byte) { b[len(b)-4] = 0x7f },
		"extension list too long":  func(b []byte) { b[5+4+2+32+1+2+4+2] = 0x7f },
	} {
		b := append([]byte(nil), good...)
		mutate(b)
		if h, ok := parseClientHello(b); ok && h.JA3 != "" {
			t.Fatalf("%s: a lying length gave a fingerprint: %+v", name, h)
		}
	}
}

func TestALengthThatLiesInsideTheServerNameExtensionIsBoundedByTheExtension(t *testing.T) {
	good := hello(0x0303, []uint16{1, 2}, sni("example.com"))
	b := append([]byte(nil), good...)
	b[5+4+2+32+1+2+4+2+2+4+1] = 0x7f // the list says it is far longer than the extension
	if h, ok := parseClientHello(b); !ok || h.SNI != "example.com" {
		t.Fatalf("%v %+v", ok, h)
	}
}

func TestAnExtensionListOneByteLongerThanTheHelloIsTruncated(t *testing.T) {
	b := hello(0x0303, []uint16{1, 2}, sni("example.com"))
	b = b[:len(b):len(b)] // nothing past the end to read by mistake
	// The list length is the two bytes before the first extension.
	i := 5 + 4 + 2 + 32 + 1 + 2 + 4 + 2
	binary.BigEndian.PutUint16(b[i:], binary.BigEndian.Uint16(b[i:])+1)
	h, ok := parseClientHello(b)
	if !ok || !h.Truncated || h.JA3 != "" || h.SNI != "example.com" {
		t.Fatalf("%v %+v", ok, h)
	}
}

func TestBytesLeftOverAfterTheLastExtensionAreNotAWholeHello(t *testing.T) {
	for n := 1; n <= 3; n++ {
		h, ok := parseClientHello(hello(0x0303, []uint16{1, 2}, sni("example.com"), make([]byte, n)))
		if !ok || !h.Truncated || h.JA3 != "" || h.SNI != "example.com" {
			t.Fatalf("%d left over: %v %+v", n, ok, h)
		}
	}
}

func TestIsGrease(t *testing.T) {
	for v := 0; v < 0x10000; v++ {
		want := v == 0x0a0a || v == 0x1a1a || v == 0x2a2a || v == 0x3a3a || v == 0x4a4a || v == 0x5a5a || v == 0x6a6a || v == 0x7a7a ||
			v == 0x8a8a || v == 0x9a9a || v == 0xaaaa || v == 0xbaba || v == 0xcaca || v == 0xdada || v == 0xeaea || v == 0xfafa
		if isGrease(uint16(v)) != want {
			t.Fatalf("%#04x: %v", v, !want)
		}
	}
}

// tlsSample lays out a tap_tls ring record by offset, the way bpf/tap.bpf.c does.
func tlsSample(family byte, flags byte, sport, dport uint16, src, dst []byte, raw []byte, rawlen int) []byte {
	b := make([]byte, tlsEventSize)
	binary.LittleEndian.PutUint32(b[8:12], 7)
	b[12], b[13] = family, flags
	binary.LittleEndian.PutUint16(b[14:16], uint16(rawlen))
	binary.LittleEndian.PutUint16(b[16:18], sport)
	binary.LittleEndian.PutUint16(b[18:20], dport)
	copy(b[24:40], src)
	copy(b[40:56], dst)
	copy(b[tlsRawOffset:], raw)
	return b
}

func ifname(i uint32) string {
	if i == 7 {
		return "vnet3"
	}
	return ""
}

func TestDecodeTLSReadsTheRecordByOffset(t *testing.T) {
	raw := hello(0x0303, []uint16{4865}, sni("Pool.Example.ORG"), ext(16, 0, 3, 2, 'h', '2'))
	e, ok := decodeTLS(tlsSample(2, 0, 40000, 443, []byte{10, 0, 0, 5}, []byte{203, 0, 113, 9}, raw, len(raw)), ifname)
	if !ok {
		t.Fatal("not decoded")
	}
	if e.Kind != event.KindGuestTLS || e.Proto != "tcp" || e.Iface != "vnet3" || e.Src != "10.0.0.5" || e.Dst != "203.0.113.9" ||
		e.DPort != 443 || e.Blocked || e.SNI != "pool.example.org" || e.ALPN != "h2" || e.TLSVersion != "1.2" || e.JA3 == "" || e.TLSTruncated || e.ECH {
		t.Fatalf("%+v", e)
	}

	src6 := []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	dst6 := []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	e, ok = decodeTLS(tlsSample(10, 1, 40000, 8443, src6, dst6, raw, len(raw)), ifname)
	if !ok || e.Src != "2001:db8::5" || e.Dst != "2001:db8::9" || e.DPort != 8443 || !e.Blocked {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestDecodeTLSOnlyTrustsWhatRawlenSays(t *testing.T) {
	// The ring record is not cleared past rawlen: what a previous hello left there must never be read.
	stale := hello(0x0303, []uint16{1}, sni("stale.example.net"))
	cut := hello(0x0303, []uint16{1, 2, 3}, ext(43, 2, 3, 4), sni("first.example.org"))
	mixed := append(append([]byte(nil), cut...), stale...)
	// Cut the copy right before the name: it must not be found in what follows.
	at := strings.Index(string(mixed), "first.example.org") - 9
	e, ok := decodeTLS(tlsSample(2, 0, 1, 443, []byte{10, 0, 0, 5}, []byte{1, 1, 1, 1}, mixed, at), ifname)
	if !ok || e.SNI != "" || !e.TLSTruncated || e.JA3 != "" {
		t.Fatalf("%v %+v", ok, e)
	}
	// A rawlen above what the ring record can hold is clamped, not trusted.
	for _, n := range []int{tlsRawMax + 1, 2000, 65535} {
		e, ok = decodeTLS(tlsSample(2, 0, 1, 443, []byte{10, 0, 0, 5}, []byte{1, 1, 1, 1}, cut, n), ifname)
		if !ok || e.SNI != "first.example.org" {
			t.Fatalf("rawlen %d: %v %+v", n, ok, e)
		}
	}
	e, ok = decodeTLS(tlsSample(2, 0, 1, 443, []byte{10, 0, 0, 5}, []byte{1, 1, 1, 1}, cut, 65535), ifname)
	if !ok || e.SNI != "first.example.org" {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestDecodeTLSRefusesWhatItCannotTrust(t *testing.T) {
	raw := hello(0x0303, []uint16{1}, sni("a.example"))
	ok4 := tlsSample(2, 0, 1, 443, []byte{10, 0, 0, 5}, []byte{1, 1, 1, 1}, raw, len(raw))
	if _, ok := decodeTLS(ok4[:tlsEventSize-1], ifname); ok {
		t.Fatal("a short sample")
	}
	if _, ok := decodeTLS(tlsSample(3, 0, 1, 443, nil, nil, raw, len(raw)), ifname); ok {
		t.Fatal("an unknown family")
	}
	unknown := append([]byte(nil), ok4...)
	binary.LittleEndian.PutUint32(unknown[8:12], 99)
	if _, ok := decodeTLS(unknown, ifname); ok {
		t.Fatal("a tap that is no longer tracked")
	}
	if _, ok := decodeTLS(tlsSample(2, 0, 1, 443, []byte{10, 0, 0, 5}, []byte{1, 1, 1, 1}, []byte("GET / HTTP/1.1\r\n"), 16), ifname); ok {
		t.Fatal("something that is not a hello")
	}
}

// A guest chooses every byte of a hello. Whatever it sends, decoding must return and stay bounded.
func TestRandomDamageToARealHelloNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for name, r := range realHellos(t) {
		full := r.bytes(t)
		for i := 0; i < 3000; i++ {
			b := append([]byte(nil), full...)
			for j := 0; j < 1+rng.Intn(6); j++ {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			b = b[:rng.Intn(len(b)+1)]
			if h, ok := parseClientHello(b); ok && (len(h.SNI) > maxSNI || len(h.ALPN) > maxALPN) {
				t.Fatalf("%s: unbounded: %d %d", name, len(h.SNI), len(h.ALPN))
			}
		}
	}
}
