//go:build linux

package observe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zyvorai/shukra/internal/event"
)

const netlinkDebounce = 50 * time.Millisecond

// WatchNetlink streams kernel routing-control-plane notifications. Link
// changes also call linksChanged after a short debounce so VM tap discovery
// can be refreshed without rescanning once per message in a burst.
func WatchNetlink(ctx context.Context, emit func(event.Event), linksChanged func()) error {
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_NEIGH |
		unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink route socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		return fmt.Errorf("bind netlink route socket: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("set netlink socket nonblocking: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)

	buf := make([]byte, 1<<16)
	var refreshAt time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		timeout := 200
		if !refreshAt.IsZero() {
			remaining := time.Until(refreshAt)
			if remaining <= 0 {
				refreshAt = time.Time{}
				if linksChanged != nil {
					linksChanged()
				}
				continue
			}
			if ms := int(remaining.Milliseconds()); ms < timeout {
				timeout = max(1, ms)
			}
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, timeout); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll netlink route socket: %w", err)
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) {
				if emit != nil {
					emit(netlinkErrorEvent(time.Now().UTC(), -int32(unix.ENOBUFS)))
				}
				continue
			}
			return fmt.Errorf("receive netlink message: %w", err)
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue // accept notifications only from the kernel
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		now := time.Now().UTC()
		for _, msg := range msgs {
			e, ok := decodeNetlink(msg, now, interfaceName)
			if !ok {
				continue
			}
			if emit != nil {
				emit(e)
			}
			if e.Kind == event.KindNetlinkLink && linksChanged != nil {
				refreshAt = time.Now().Add(netlinkDebounce)
			}
		}
	}
}

// WatchLinks preserves the old rescan-only API.
func WatchLinks(ctx context.Context, fn func()) { _ = WatchNetlink(ctx, nil, fn) }

func interfaceName(index int32) string {
	if index <= 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return ""
	}
	return iface.Name
}

func decodeNetlink(msg syscall.NetlinkMessage, now time.Time, name func(int32) string) (event.Event, bool) {
	action := "new"
	switch msg.Header.Type {
	case unix.RTM_DELLINK, unix.RTM_DELADDR, unix.RTM_DELROUTE, unix.RTM_DELNEIGH:
		action = "delete"
	case unix.NLMSG_ERROR:
		if len(msg.Data) < 4 {
			return event.Event{}, false
		}
		code := int32(binary.NativeEndian.Uint32(msg.Data[:4]))
		if code == 0 {
			return event.Event{}, false
		}
		return netlinkErrorEvent(now, code), true
	}

	n := &event.Netlink{Action: action}
	e := event.Event{TS: now, Attribution: event.AttributionHostNetlink, Netlink: n}
	headerLen := 0
	switch msg.Header.Type {
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		headerLen = unix.SizeofIfInfomsg
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		headerLen = unix.SizeofIfAddrmsg
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		headerLen = unix.SizeofRtMsg
	case unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
		headerLen = unix.SizeofNdMsg
	default:
		return event.Event{}, false
	}
	attrs, ok := parseRouteAttrs(msg.Data, headerLen)
	if !ok {
		return event.Event{}, false
	}
	switch msg.Header.Type {
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		e.Kind, n.Object = event.KindNetlinkLink, "link"
		n.Family = familyName(msg.Data[0])
		n.IfIndex = int32(binary.NativeEndian.Uint32(msg.Data[4:8]))
		n.Flags = binary.NativeEndian.Uint32(msg.Data[8:12])
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.IFLA_IFNAME:
				n.Interface = nulString(a.Value)
			case unix.IFLA_MTU:
				n.MTU = u32(a.Value)
			case unix.IFLA_LINK:
				n.ParentIndex = int32(u32(a.Value))
			case unix.IFLA_MASTER:
				n.MasterIndex = int32(u32(a.Value))
			case unix.IFLA_OPERSTATE:
				if len(a.Value) > 0 {
					n.OperState = operStateName(a.Value[0])
				}
			}
		}
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		e.Kind, n.Object = event.KindNetlinkAddress, "address"
		n.Family, n.PrefixLen, n.Scope = familyName(msg.Data[0]), msg.Data[1], msg.Data[3]
		n.IfIndex = int32(binary.NativeEndian.Uint32(msg.Data[4:8]))
		for _, a := range attrs {
			if a.Attr.Type == unix.IFA_LOCAL || (a.Attr.Type == unix.IFA_ADDRESS && n.Address == "") {
				n.Address = ipString(msg.Data[0], a.Value)
			}
			if a.Attr.Type == unix.IFA_LABEL {
				n.Interface = nulString(a.Value)
			}
		}
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		e.Kind, n.Object = event.KindNetlinkRoute, "route"
		n.Family, n.PrefixLen, n.Table = familyName(msg.Data[0]), msg.Data[1], uint32(msg.Data[4])
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.RTA_DST:
				n.Destination = ipString(msg.Data[0], a.Value)
			case unix.RTA_GATEWAY:
				n.Gateway = ipString(msg.Data[0], a.Value)
			case unix.RTA_OIF:
				n.IfIndex = int32(u32(a.Value))
			case unix.RTA_PRIORITY:
				n.Priority = u32(a.Value)
			case unix.RTA_TABLE:
				n.Table = u32(a.Value)
			}
		}
		if n.Destination == "" {
			if n.Family == "ipv6" {
				n.Destination = "::/0"
			} else {
				n.Destination = "0.0.0.0/0"
			}
		} else {
			n.Destination = fmt.Sprintf("%s/%d", n.Destination, n.PrefixLen)
		}
	case unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
		e.Kind, n.Object = event.KindNetlinkNeighbor, "neighbor"
		n.Family = familyName(msg.Data[0])
		n.IfIndex = int32(binary.NativeEndian.Uint32(msg.Data[4:8]))
		n.State = neighborStateName(binary.NativeEndian.Uint16(msg.Data[8:10]))
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.NDA_DST:
				n.Address = ipString(msg.Data[0], a.Value)
			case unix.NDA_LLADDR:
				n.LLAddr = net.HardwareAddr(a.Value).String()
			}
		}
	}
	if n.Interface == "" && name != nil {
		n.Interface = name(n.IfIndex)
	}
	event.Normalize(&e)
	return e, true
}

// parseRouteAttrs handles every rtnetlink object we subscribe to, including
// neighbors, which syscall.ParseNetlinkRouteAttr does not support.
func parseRouteAttrs(data []byte, headerLen int) ([]syscall.NetlinkRouteAttr, bool) {
	if headerLen < 0 || len(data) < headerLen {
		return nil, false
	}
	b := data[headerLen:]
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		if length < unix.SizeofRtAttr || length > len(b) {
			return nil, false
		}
		kind := binary.NativeEndian.Uint16(b[2:4])
		attrs = append(attrs, syscall.NetlinkRouteAttr{
			Attr:  syscall.RtAttr{Len: uint16(length), Type: kind},
			Value: b[unix.SizeofRtAttr:length],
		})
		step := (length + 3) &^ 3
		if step > len(b) {
			if length != len(b) {
				return nil, false
			}
			step = len(b)
		}
		b = b[step:]
	}
	if len(b) != 0 {
		return nil, false
	}
	return attrs, true
}

func netlinkErrorEvent(now time.Time, code int32) event.Event {
	e := event.Event{Kind: event.KindNetlinkError, TS: now, Attribution: event.AttributionHostNetlink,
		Netlink: &event.Netlink{Action: "error", Object: "netlink", Error: code}}
	event.Normalize(&e)
	return e
}

func u32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(b[:4])
}

func nulString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func familyName(f byte) string {
	switch f {
	case unix.AF_INET:
		return "ipv4"
	case unix.AF_INET6:
		return "ipv6"
	case unix.AF_UNSPEC:
		return "unspecified"
	default:
		return fmt.Sprintf("family-%d", f)
	}
}

func ipString(family byte, b []byte) string {
	switch family {
	case unix.AF_INET:
		if len(b) >= net.IPv4len {
			return net.IP(b[:net.IPv4len]).String()
		}
	case unix.AF_INET6:
		if len(b) >= net.IPv6len {
			return net.IP(b[:net.IPv6len]).String()
		}
	}
	return ""
}

func operStateName(v byte) string {
	names := [...]string{"unknown", "not-present", "down", "lower-layer-down", "testing", "dormant", "up"}
	if int(v) < len(names) {
		return names[v]
	}
	return fmt.Sprintf("state-%d", v)
}

func neighborStateName(v uint16) string {
	if v == 0 {
		return "none"
	}
	var out string
	states := []struct {
		bit  uint16
		name string
	}{
		{unix.NUD_INCOMPLETE, "incomplete"}, {unix.NUD_REACHABLE, "reachable"},
		{unix.NUD_STALE, "stale"}, {unix.NUD_DELAY, "delay"}, {unix.NUD_PROBE, "probe"},
		{unix.NUD_FAILED, "failed"}, {unix.NUD_NOARP, "noarp"}, {unix.NUD_PERMANENT, "permanent"},
	}
	for _, s := range states {
		if v&s.bit != 0 {
			if out != "" {
				out += ","
			}
			out += s.name
		}
	}
	return out
}
