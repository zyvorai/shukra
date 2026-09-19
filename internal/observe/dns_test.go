package observe

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

// wire builds a question section: length-prefixed labels, a zero byte, and the type and class.
func wire(name string, qtype uint16) []byte {
	var b []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b
}

func TestParseQNameFoldsCaseAndReadsTheType(t *testing.T) {
	for _, x := range []struct {
		in    string
		qtype uint16
		want  string
	}{
		{"example.com", 1, "example.com"},
		{"WwW.ExAmPlE.CoM", 28, "www.example.com"},
		{"_sip._tcp.example.com", 33, "_sip._tcp.example.com"},
		{"a", 65, "a"},
	} {
		name, qt, done, ok := parseQName(wire(x.in, x.qtype))
		if name != x.want || qt != x.qtype || !done || !ok {
			t.Errorf("%q: got %q %d done=%v ok=%v", x.in, name, qt, done, ok)
		}
	}
}

func TestParseQNameRootIsEmptyAndDecodeCallsItADot(t *testing.T) {
	name, qt, done, ok := parseQName(wire("", 2))
	if name != "" || qt != 2 || !done || !ok {
		t.Fatalf("%q %d %v %v", name, qt, done, ok)
	}
}

func TestParseQNameRefusesWhatIsNotAPlainFirstQuestion(t *testing.T) {
	// 0xC0 is a compression pointer, and 0x40 to 0xBF are extensions: neither belongs in a first question.
	for _, first := range []byte{0xC0, 0x40, 0x80, 0xFF} {
		if _, _, _, ok := parseQName([]byte{3, 'a', 'b', 'c', first, 0x0c, 0}); ok {
			t.Errorf("accepted a length byte of %#x", first)
		}
	}
}

func TestParseQNameOnANameThatDoesNotEndIsMarkedUnfinishedNotGuessed(t *testing.T) {
	// A label that runs past what was copied keeps what there is and says it is not finished.
	name, _, done, ok := parseQName([]byte{3, 'a', 'b', 'c', 9, 'x', 'y'})
	if name != "abc.xy" || done || !ok {
		t.Fatalf("%q done=%v ok=%v", name, done, ok)
	}
	// Ending exactly at a label boundary, with no terminator: unfinished too.
	name, _, done, ok = parseQName([]byte{3, 'a', 'b', 'c'})
	if name != "abc" || done || !ok {
		t.Fatalf("%q done=%v ok=%v", name, done, ok)
	}
	// Terminated, but the type is missing.
	name, qt, done, ok := parseQName([]byte{3, 'a', 'b', 'c', 0, 0})
	if name != "abc" || qt != 0 || done || !ok {
		t.Fatalf("%q %d done=%v ok=%v", name, qt, done, ok)
	}
	if _, _, done, ok := parseQName(nil); done || !ok {
		t.Fatal("nothing at all is not a finished name")
	}
}

func TestParseQNameCannotBeUsedToSmuggleControlCharacters(t *testing.T) {
	raw := []byte{6, 'a', '\n', 'b', 0x1b, '[', 'm', 3, 'c', ' ', 0xff, 0, 0, 1}
	name, _, done, ok := parseQName(raw)
	if !ok || !done {
		t.Fatal("a name with odd bytes is still a name")
	}
	for _, c := range name {
		if c < 0x21 || c > 0x7e {
			t.Fatalf("%q carries a byte a log or a terminal would act on", name)
		}
	}
	if name != "a?b?[m.c??" {
		t.Fatalf("%q", name)
	}
}

func TestParseQNameStopsAtTheMaximumNameLength(t *testing.T) {
	label := strings.Repeat("a", 60)
	var raw []byte
	for i := 0; i < 6; i++ { // more than a DNS name can be, which the kernel never copies, but a decoder must not trust that
		raw = append(raw, 60)
		raw = append(raw, label...)
	}
	name, _, done, ok := parseQName(raw)
	if !ok || done || len(name) != maxDNSName {
		t.Fatalf("len=%d done=%v ok=%v", len(name), done, ok)
	}
}

// sample builds a ring record the way bpf/tap.bpf.c lays it out.
func sample(family, flags byte, src, dst []byte, question []byte) []byte {
	b := make([]byte, dnsEventSize)
	binary.LittleEndian.PutUint64(b[0:], 12345)
	binary.LittleEndian.PutUint32(b[8:], 7)
	b[12], b[13] = family, flags
	n := min(len(question), dnsRawMax)
	binary.LittleEndian.PutUint16(b[14:], uint16(n))
	copy(b[16:32], src)
	copy(b[32:48], dst)
	copy(b[dnsRawOffset:], question[:n])
	return b
}

func tapNamed(idx uint32) string {
	if idx == 7 {
		return "tap7"
	}
	return ""
}

func TestDecodeDNSReadsTheRecordByOffset(t *testing.T) {
	e, ok := decodeDNS(sample(2, 0, []byte{10, 0, 0, 5}, []byte{10, 0, 0, 1}, wire("Example.COM", 28)), tapNamed)
	if !ok {
		t.Fatal("did not decode")
	}
	if e.Kind != event.KindGuestDNS || e.Iface != "tap7" || e.Src != "10.0.0.5" || e.Dst != "10.0.0.1" || e.DPort != 53 || e.Proto != "udp" ||
		e.DNSName != "example.com" || e.QType != "AAAA" || e.Blocked || e.DNSTruncated {
		t.Fatalf("%+v", e)
	}
}

func TestDecodeDNSIPv6BlockedAndUnknownType(t *testing.T) {
	src := []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	dst := []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	e, ok := decodeDNS(sample(10, dnsFlagBlocked, src, dst, wire("x.test", 999)), tapNamed)
	if !ok || e.Src != "fd00::5" || e.Dst != "fd00::1" || !e.Blocked || e.QType != "TYPE999" {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestDecodeDNSMarksANameThatDidNotFit(t *testing.T) {
	var q []byte
	for len(q) < dnsRawMax {
		q = append(q, 30)
		q = append(q, strings.Repeat("z", 30)...)
	}
	e, ok := decodeDNS(sample(2, dnsFlagUnfinished, []byte{10, 0, 0, 5}, []byte{10, 0, 0, 1}, q), tapNamed)
	if !ok || !e.DNSTruncated || e.QType != "" || !strings.HasPrefix(e.DNSName, "zzzz") {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestDecodeDNSRefusesWhatItCannotTrust(t *testing.T) {
	good := sample(2, 0, []byte{10, 0, 0, 5}, []byte{10, 0, 0, 1}, wire("a.test", 1))
	if _, ok := decodeDNS(good[:dnsEventSize-1], tapNamed); ok {
		t.Error("a short record decoded")
	}
	bad := append([]byte(nil), good...)
	bad[12] = 3
	if _, ok := decodeDNS(bad, tapNamed); ok {
		t.Error("an unknown family decoded")
	}
	bad = append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(bad[8:], 99) // a tap we no longer track
	if _, ok := decodeDNS(bad, tapNamed); ok {
		t.Error("an event for a tap nobody tracks decoded")
	}
	bad = append([]byte(nil), good...)
	bad[dnsRawOffset] = 0xC0
	if _, ok := decodeDNS(bad, tapNamed); ok {
		t.Error("a compression pointer decoded")
	}
	bad = append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(bad[14:], 60000) // a length larger than the field must not read past it
	if _, ok := decodeDNS(bad, tapNamed); !ok {
		t.Error("an oversized length must be clamped, not refused or read past the record")
	}
}

func TestTheRootNameIsADotAndTheTypeNamesAreTheCommonOnes(t *testing.T) {
	e, ok := decodeDNS(sample(2, 0, []byte{10, 0, 0, 5}, []byte{10, 0, 0, 1}, wire("", 2)), tapNamed)
	if !ok || e.DNSName != "." || e.QType != "NS" {
		t.Fatalf("%v %+v", ok, e)
	}
	for n, want := range map[uint16]string{1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 12: "PTR", 65: "HTTPS", 255: "ANY", 0: "TYPE0"} {
		if got := qtypeName(n); got != want {
			t.Errorf("%d: %s, want %s", n, got, want)
		}
	}
}
