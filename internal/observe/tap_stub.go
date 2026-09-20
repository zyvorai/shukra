//go:build !shukrabpf

package observe

import (
	"net/netip"

	"github.com/zyvorai/shukra/internal/event"
)

// ShutdownTaps has nothing to detach in this build.
func ShutdownTaps() {}

// DetachAllTaps has nothing to detach in this build.
func DetachAllTaps() int { return 0 }

// SyncTaps does nothing in this build: there is no program to attach.
func SyncTaps([]string) {}

// TapProgram is the state of the tap program.
func TapProgram() (status, detail string) {
	return "detached", "CO-RE objects are not linked in this binary. On Linux: make generate && go build -tags shukrabpf."
}

// TapSample is nil here. The daemon must not invent counters.
func TapSample() []TapCounters { return nil }

// SetDNSEvents has no program to tell in this build.
func SetDNSEvents(bool) {}

// SetTLSEvents has no program to tell in this build.
func SetTLSEvents(bool) {}

// StartTap reads no ring in this build.
func StartTap(func(event.Event)) {}

// Enforcer refuses everything in this build, and says why.
type Enforcer struct{}

// NewEnforcer returns an Enforcer that cannot enforce.
func NewEnforcer([]netip.Prefix) *Enforcer { return &Enforcer{} }

func (*Enforcer) Available() (bool, string) {
	return false, "this build has no BPF programs, so nothing can be enforced"
}
func (*Enforcer) AllowList() []string                { return nil }
func (*Enforcer) Durable() bool                      { return false }
func (*Enforcer) Isolated(string) bool               { return false }
func (*Enforcer) Isolate([]string) ([]string, error) { return nil, errNoBPF }
func (*Enforcer) Release([]string) ([]string, error) { return nil, errNoBPF }

type noBPF struct{}

func (noBPF) Error() string { return "this build has no BPF programs" }

var errNoBPF error = noBPF{}

// EgressKernel cannot reach a kernel program in this build.
type EgressKernel struct{}

// NewEgressKernel returns an EgressKernel that cannot set anything.
func NewEgressKernel(*Enforcer) *EgressKernel { return &EgressKernel{} }

func (*EgressKernel) Available() (bool, string) {
	return false, "this build has no BPF programs, so no policy can be set"
}
func (*EgressKernel) CanEnforce() (bool, string) {
	return false, "this build has no BPF programs, so nothing can be enforced"
}
func (*EgressKernel) Set(string, uint8, []netip.Prefix) error { return errNoBPF }
func (*EgressKernel) Mode(string) uint8                       { return 0 }
func (*EgressKernel) Stats() []EgressCounters                 { return nil }

// StartVMM reads no ring in this build.
func StartVMM(func(event.Event)) {}

// DisableVMM has no program to keep out in this build.
func DisableVMM() {}
