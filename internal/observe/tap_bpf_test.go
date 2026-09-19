//go:build shukrabpf && linux

package observe

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

func tapSample(family byte) []byte {
	b := make([]byte, tapEventSize)
	binary.LittleEndian.PutUint32(b[8:12], 7)
	binary.LittleEndian.PutUint16(b[12:14], 8080)
	binary.LittleEndian.PutUint16(b[14:16], 41000)
	b[16] = family
	b[18] = 6 // a TCP connect, unless a test says otherwise
	return b
}

func TestDecodeTapInboundConnect(t *testing.T) {
	// A SYN sent TO the guest: dir is 1, src is the peer that connected, dst is the guest, dport the guest's port.
	b := tapSample(2)
	b[19] = 1
	binary.LittleEndian.PutUint16(b[12:14], 22)
	copy(b[24:28], net.ParseIP("198.51.100.7").To4())
	copy(b[40:44], net.ParseIP("10.99.0.2").To4())
	e, ok := decodeTap(b, nameOf)
	if !ok || e.Kind != event.KindGuestInbound || e.Proto != "tcp" || e.Src != "198.51.100.7" || e.Dst != "10.99.0.2" || e.DPort != 22 {
		t.Fatalf("%+v %v", e, ok)
	}
	b[19] = 0 // the guest's own connect is still a connect
	if e, ok = decodeTap(b, nameOf); !ok || e.Kind != event.KindGuestConnect {
		t.Fatalf("%+v %v", e, ok)
	}
}

func nameOf(idx uint32) string {
	if idx == 7 {
		return "tapdb"
	}
	return ""
}

func TestDecodeTapIPv4(t *testing.T) {
	b := tapSample(2)
	copy(b[24:28], net.ParseIP("10.99.0.2").To4())
	copy(b[40:44], net.ParseIP("10.99.0.3").To4())
	b[17] = 1
	e, ok := decodeTap(b, nameOf)
	if !ok || e.Kind != event.KindGuestConnect || e.Iface != "tapdb" || e.Src != "10.99.0.2" || e.Dst != "10.99.0.3" || e.DPort != 8080 || !e.Blocked {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestDecodeTapIPv6(t *testing.T) {
	b := tapSample(10)
	copy(b[24:40], net.ParseIP("fd99::2"))
	copy(b[40:56], net.ParseIP("fd99::3"))
	e, ok := decodeTap(b, nameOf)
	if !ok || e.Src != "fd99::2" || e.Dst != "fd99::3" || e.Blocked {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestDecodeTapRejectsWhatItCannotTrust(t *testing.T) {
	if _, ok := decodeTap(make([]byte, 20), nameOf); ok {
		t.Fatal("a short record was accepted")
	}
	if _, ok := decodeTap(tapSample(0), nameOf); ok {
		t.Fatal("an unknown address family was accepted")
	}
	stray := tapSample(2)
	binary.LittleEndian.PutUint32(stray[8:12], 99) // an interface we no longer track
	if _, ok := decodeTap(stray, nameOf); ok {
		t.Fatal("an event for an untracked interface was accepted")
	}
}

func TestDecodeTapUDPFlow(t *testing.T) {
	b := tapSample(2)
	b[18] = 17
	copy(b[24:28], net.ParseIP("10.99.0.2").To4())
	copy(b[40:44], net.ParseIP("10.99.0.1").To4())
	e, ok := decodeTap(b, nameOf)
	if !ok || e.Kind != event.KindGuestFlow || e.Proto != "udp" || e.Dst != "10.99.0.1" {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestDecodeTapTreatsProtoZeroAsTCPForAnUpgrade(t *testing.T) {
	// During an upgrade the previous program can still emit events from before the
	// field existed. They were TCP connects and must not be dropped.
	b := tapSample(2)
	b[18] = 0
	copy(b[40:44], net.ParseIP("10.99.0.1").To4())
	e, ok := decodeTap(b, nameOf)
	if !ok || e.Kind != event.KindGuestConnect || e.Proto != "tcp" {
		t.Fatalf("%+v %v", e, ok)
	}
	b[18] = 1 // ICMP: not something this program emits
	if _, ok := decodeTap(b, nameOf); ok {
		t.Fatal("an unknown protocol was accepted")
	}
}
