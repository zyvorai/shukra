//go:build linux

package observe

import (
	"context"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WatchLinks calls fn when a network interface appears or disappears. The
// two-second scan remains the backstop. A burst of messages is one call.
func WatchLinks(ctx context.Context, fn func()) {
	if fn == nil {
		return
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
		return
	}
	_ = unix.SetNonblock(fd, true)
	pending := make(chan struct{}, 1)
	go func() {
		var quiet <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-pending:
				quiet = time.After(50 * time.Millisecond)
			case <-quiet:
				quiet = nil
				fn()
			}
		}
	}()
	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 200); err != nil && err != unix.EINTR {
			continue
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type == unix.RTM_NEWLINK || m.Header.Type == unix.RTM_DELLINK {
				select {
				case pending <- struct{}{}:
				default:
				}
				break
			}
		}
	}
}
