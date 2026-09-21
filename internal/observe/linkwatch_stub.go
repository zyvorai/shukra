//go:build !linux

package observe

import (
	"context"

	"github.com/zyvorai/shukra/internal/event"
)

func WatchNetlink(context.Context, func(event.Event), func()) error { return nil }

// WatchLinks preserves the old rescan-only API off Linux.
func WatchLinks(context.Context, func()) {}
