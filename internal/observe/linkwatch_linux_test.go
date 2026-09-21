//go:build linux

package observe

import (
	"encoding/binary"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zyvorai/shukra/internal/event"
)

func attr(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b[0:2], uint16(n))
	binary.NativeEndian.PutUint16(b[2:4], kind)
	copy(b[4:], value)
	return b
}

func u32bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestDecodeNetlinkLink(t *testing.T) {
	h := make([]byte, unix.SizeofIfInfomsg)
	h[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(h[4:8], 12)
	binary.NativeEndian.PutUint32(h[8:12], unix.IFF_UP)
	b := append(h, attr(unix.IFLA_IFNAME, []byte("tap12\x00"))...)
	b = append(b, attr(unix.IFLA_MTU, u32bytes(1500))...)
	b = append(b, attr(unix.IFLA_OPERSTATE, []byte{6})...)
	e, ok := decodeNetlink(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK}, Data: b}, time.Unix(1, 0), nil)
	if !ok || e.Kind != event.KindNetlinkLink || e.Netlink.Interface != "tap12" || e.Netlink.MTU != 1500 || e.Netlink.OperState != "up" {
		t.Fatalf("unexpected event: %#v, ok=%v", e, ok)
	}
}

func TestDecodeNetlinkAddress(t *testing.T) {
	h := make([]byte, unix.SizeofIfAddrmsg)
	h[0], h[1], h[3] = unix.AF_INET, 24, unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(h[4:8], 4)
	b := append(h, attr(unix.IFA_LOCAL, []byte{10, 0, 0, 8})...)
	e, ok := decodeNetlink(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWADDR}, Data: b}, time.Unix(1, 0), func(int32) string { return "eth0" })
	if !ok || e.Netlink.Address != "10.0.0.8" || e.Netlink.PrefixLen != 24 || e.Netlink.Interface != "eth0" {
		t.Fatalf("unexpected event: %#v, ok=%v", e, ok)
	}
}

func TestDecodeNetlinkDefaultRouteAndDelete(t *testing.T) {
	h := make([]byte, unix.SizeofRtMsg)
	h[0], h[1], h[4] = unix.AF_INET6, 0, unix.RT_TABLE_MAIN
	b := append(h, attr(unix.RTA_GATEWAY, []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	b = append(b, attr(unix.RTA_OIF, u32bytes(7))...)
	e, ok := decodeNetlink(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_DELROUTE}, Data: b}, time.Unix(1, 0), nil)
	if !ok || e.Kind != event.KindNetlinkRoute || e.Netlink.Action != "delete" || e.Netlink.Destination != "::/0" || e.Netlink.Gateway != "fe80::1" {
		t.Fatalf("unexpected event: %#v, ok=%v", e, ok)
	}
}

func TestDecodeNetlinkNeighbor(t *testing.T) {
	h := make([]byte, unix.SizeofNdMsg)
	h[0] = unix.AF_INET
	binary.NativeEndian.PutUint32(h[4:8], 9)
	binary.NativeEndian.PutUint16(h[8:10], unix.NUD_FAILED)
	b := append(h, attr(unix.NDA_DST, []byte{192, 0, 2, 9})...)
	b = append(b, attr(unix.NDA_LLADDR, []byte{0, 1, 2, 3, 4, 5})...)
	e, ok := decodeNetlink(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEIGH}, Data: b}, time.Unix(1, 0), nil)
	if !ok || e.Kind != event.KindNetlinkNeighbor || e.Netlink.State != "failed" || e.Netlink.LLAddr != "00:01:02:03:04:05" {
		t.Fatalf("unexpected event: %#v, ok=%v", e, ok)
	}
}

func TestDecodeNetlinkRejectsShortMessage(t *testing.T) {
	if _, ok := decodeNetlink(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK}, Data: []byte{1}}, time.Time{}, nil); ok {
		t.Fatal("short message accepted")
	}
}

func TestParseRouteAttrsRejectsInvalidLength(t *testing.T) {
	b := make([]byte, unix.SizeofNdMsg+unix.SizeofRtAttr)
	binary.NativeEndian.PutUint16(b[unix.SizeofNdMsg:], 2)
	if _, ok := parseRouteAttrs(b, unix.SizeofNdMsg); ok {
		t.Fatal("invalid attribute length accepted")
	}
}
