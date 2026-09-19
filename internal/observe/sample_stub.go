//go:build !shukrabpf

package observe

import (
	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
)

// Sample is nil in this build. The daemon must not invent counters.
func Sample() map[uint32]aggregate.Counters { return nil }

// Start does not read a ring. There is no program attached.
func Start(func(event.Event)) {}
