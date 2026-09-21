package agent

import (
	"testing"

	"github.com/zyvorai/shukra/internal/identity"
)

func TestAnEnforcingVMWithALiveTapAndNoProgramIsUncovered(t *testing.T) {
	vms := []identity.VM{{Name: "web", Taps: []string{"tap0", "tap1"}}}
	mode := func(vm string) string {
		if vm == "web" {
			return "enforce"
		}
		return "off"
	}
	live := func(tap string) bool { return tap == "tap0" || tap == "tap1" }
	got := enforcingGaps(vms, mode, map[string]bool{"tap1": true}, live)
	if len(got) != 1 || got[0].tap != "tap0" {
		t.Fatalf("%+v", got)
	}
	if g := enforcingGaps(vms, func(string) string { return "audit" }, nil, live); len(g) != 0 {
		t.Fatalf("audit is not a coverage gap: %+v", g)
	}
}

func TestQuarantineIsOnlyForAnAttachedTapStillWaitingOnItsPolicy(t *testing.T) {
	vms := []identity.VM{{Name: "web", Taps: []string{"tap0", "tap1"}}}
	saved := func(string) string { return "enforce" }
	kernel := func(_, tap string) string {
		if tap == "tap1" {
			return "enforce"
		}
		return "off"
	}
	got := quarantineTaps(vms, saved, kernel, map[string]bool{"tap0": true, "tap1": true})
	if len(got) != 1 || got[0] != "tap0" {
		t.Fatalf("%+v", got)
	}
	done := func(_, _ string) string { return "enforce" }
	if g := quarantineTaps(vms, saved, done, map[string]bool{"tap0": true}); len(g) != 0 {
		t.Fatalf("a tap that already has its policy is not quarantined: %+v", g)
	}
}
