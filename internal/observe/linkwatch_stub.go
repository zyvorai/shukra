//go:build !linux

package observe

import "context"

// WatchLinks does nothing off Linux. The refresh ticker is the only scan.
func WatchLinks(context.Context, func()) {}
