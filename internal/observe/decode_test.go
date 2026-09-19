package observe

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

func TestDecodeRingConnect(t *testing.T) {
	b := make([]byte, ringEventSize)
	binary.LittleEndian.PutUint32(b[8:12], 101)
	binary.LittleEndian.PutUint32(b[12:16], 100)
	binary.LittleEndian.PutUint32(b[16:20], 2)
	binary.LittleEndian.PutUint16(b[20:22], 443)
	binary.LittleEndian.PutUint16(b[22:24], familyInet)
	binary.LittleEndian.PutUint32(b[24:28], 1|2<<8|3<<16|4<<24)
	copy(b[40:], "qemu-system-x86")
	e, ok := DecodeRing(b)
	if !ok {
		t.Fatal("expected ok")
	}
	if e.Kind != event.KindTCPConnect || e.PID != 101 || e.TGID != 100 || e.DPort != 443 || e.Dst != "1.2.3.4" || e.Comm != "qemu-system-x86" {
		t.Fatalf("%+v", e)
	}
}

func TestDecodeRingRejectsShort(t *testing.T) {
	if _, ok := DecodeRing([]byte{1, 2, 3}); ok {
		t.Fatal("short record should be lost")
	}
}

func TestDecodeRingIPv6Connect(t *testing.T) {
	b := make([]byte, ringEventSize)
	binary.LittleEndian.PutUint32(b[16:20], 2)
	binary.LittleEndian.PutUint16(b[20:22], 8443)
	binary.LittleEndian.PutUint16(b[22:24], familyInet6)
	copy(b[56:72], net.ParseIP("2001:db8::1"))
	e, ok := DecodeRing(b)
	if !ok || e.Dst != "2001:db8::1" || e.DPort != 8443 {
		t.Fatalf("%+v %v", e, ok)
	}
	// The v4 field is ignored for a v6 record, even when it holds junk.
	binary.LittleEndian.PutUint32(b[24:28], 0xdeadbeef)
	if e, _ = DecodeRing(b); e.Dst != "2001:db8::1" {
		t.Fatalf("v4 junk leaked into a v6 destination: %q", e.Dst)
	}
}

func TestDecodeRingFamilyDecidesWhichAddressIsRead(t *testing.T) {
	b := make([]byte, ringEventSize)
	binary.LittleEndian.PutUint32(b[16:20], 3)
	binary.LittleEndian.PutUint32(b[24:28], 9|9<<8|9<<16|9<<24)
	copy(b[56:72], net.ParseIP("2001:db8::1"))
	// No family: neither address is trusted.
	if e, _ := DecodeRing(b); e.Dst != "" {
		t.Fatalf("family 0 produced a destination %q", e.Dst)
	}
	binary.LittleEndian.PutUint16(b[22:24], familyInet)
	if e, _ := DecodeRing(b); e.Dst != "9.9.9.9" {
		t.Fatalf("%q", e.Dst)
	}
}

func TestDecodeRingCarriesParentPID(t *testing.T) {
	b := make([]byte, ringEventSize)
	binary.LittleEndian.PutUint32(b[8:12], 4242)
	binary.LittleEndian.PutUint32(b[16:20], 6) // exit
	binary.LittleEndian.PutUint32(b[28:32], 100)
	e, ok := DecodeRing(b)
	if !ok || e.Kind != event.KindExit || e.PID != 4242 || e.PPID != 100 {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestDecodeRingRejectsTheOldSize(t *testing.T) {
	if _, ok := DecodeRing(make([]byte, 56)); ok {
		t.Fatal("a 56-byte record from the previous layout was accepted")
	}
}
