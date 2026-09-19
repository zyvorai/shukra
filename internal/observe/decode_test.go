package observe

import (
	"encoding/binary"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

func TestDecodeRingConnect(t *testing.T) {
	b := make([]byte, ringEventSize)
	binary.LittleEndian.PutUint32(b[8:12], 101)
	binary.LittleEndian.PutUint32(b[12:16], 100)
	binary.LittleEndian.PutUint32(b[16:20], 2)
	binary.LittleEndian.PutUint16(b[20:22], 443)
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
