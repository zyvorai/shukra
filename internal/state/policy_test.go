package state

import (
	"strings"
	"testing"
	"time"
)

type policyStub struct {
	rows      []PolicyRow
	orphans   []PolicyOrphan
	persisted bool
}

func (p policyStub) List() []PolicyRow                    { return p.rows }
func (p policyStub) Get(string) (PolicyRow, bool)         { return PolicyRow{}, false }
func (p policyStub) Learn(string) (PolicyProposal, error) { return PolicyProposal{}, nil }
func (p policyStub) Apply(string, PolicyRequest, string) (PolicyRow, error) {
	return PolicyRow{}, nil
}
func (p policyStub) Confirm(string, string) (PolicyRow, error) { return PolicyRow{}, nil }
func (p policyStub) Remove(string, string) (PolicyRow, error)  { return PolicyRow{}, nil }
func (p policyStub) Orphans() []PolicyOrphan                   { return p.orphans }
func (p policyStub) Persisted() bool                           { return p.persisted }

func TestDoctorSaysNothingAboutEgressPolicyUnlessAVMHasOneOrTheKernelAppliesOneNobodyRecorded(t *testing.T) {
	st := healthy(t)
	if byID(st.Doctor(), "egress-policy") != nil {
		t.Fatal("noise")
	}
	st.SetPolicy(policyStub{})
	if byID(st.Doctor(), "egress-policy") != nil {
		t.Fatal("an engine with no policies has nothing to say")
	}
}

func TestDoctorCountsThePoliciesAndWhatAuditWouldHaveDropped(t *testing.T) {
	st := healthy(t)
	st.SetPolicy(policyStub{rows: []PolicyRow{
		{VM: "web", Mode: "audit", Taps: []PolicyTap{{Tap: "t1", AuditPkts: 5}, {Tap: "t2", AuditPkts: 2}}},
		{VM: "db", Mode: "enforce", Taps: []PolicyTap{{Tap: "t3", AuditPkts: 0, DroppedPkts: 9}}},
		{VM: "cache", Mode: "audit"},
	}})
	c := byID(st.Doctor(), "egress-policy")
	if c == nil || c.Status != "ok" || c.Title != "Egress policy is on for 3 VMs (2 audit, 1 enforce)" || !strings.HasPrefix(c.Detail, "7 new connections or datagrams would have been dropped in audit mode") {
		t.Fatalf("%+v", c)
	}
	st.SetPolicy(policyStub{rows: []PolicyRow{{VM: "web", Mode: "enforce"}}})
	if c := byID(st.Doctor(), "egress-policy"); c == nil || c.Detail != "" {
		t.Fatalf("nothing would have been dropped, so nothing is said: %+v", c)
	}
}

func TestDoctorWarnsOfAnEnforcingPolicyWaitingToBeConfirmed(t *testing.T) {
	st := healthy(t)
	until := time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC)
	st.SetPolicy(policyStub{rows: []PolicyRow{{VM: "web", Mode: "enforce", Revert: &PolicyRevert{Until: until, To: "audit with 3 networks"}}, {VM: "db", Mode: "audit"}}})
	c := byID(st.Doctor(), "egress-policy")
	if c == nil || c.Status != "warn" || !strings.HasPrefix(c.Title, "1 enforcing egress policies are waiting") ||
		!strings.Contains(c.Detail, "web goes back to audit with 3 networks at 2026-09-20T04:00:00Z") || !strings.Contains(c.Fix, "shukractl policy confirm") {
		t.Fatalf("%+v", c)
	}
}

func TestDoctorWarnsWhenTheKernelIsNotDoingWhatAPolicySays(t *testing.T) {
	st := healthy(t)
	st.SetPolicy(policyStub{rows: []PolicyRow{{VM: "web", Mode: "enforce", Problem: "the kernel has tapweb in mode off, and the policy says enforce"}}})
	c := byID(st.Doctor(), "egress-policy")
	if c == nil || c.Status != "warn" || c.Title != "The kernel is not doing what an egress policy says" || !strings.Contains(c.Detail, "web: the kernel has tapweb in mode off") {
		t.Fatalf("%+v", c)
	}
}

func TestATapEnforcingAPolicyNobodyRecordedOutranksEverythingElse(t *testing.T) {
	st := healthy(t)
	st.SetPolicy(policyStub{
		orphans: []PolicyOrphan{{VM: "web", Tap: "tapweb", Mode: "enforce"}},
		rows:    []PolicyRow{{VM: "db", Mode: "enforce", Problem: "x", Revert: &PolicyRevert{Until: time.Now(), To: "no policy"}}},
	})
	c := byID(st.Doctor(), "egress-policy")
	if c == nil || c.Status != "warn" || c.Title != "1 taps apply an egress policy that nobody has a record of" || !strings.Contains(c.Detail, "web (tapweb, enforce)") || !strings.Contains(c.Fix, "shukractl policy remove") {
		t.Fatalf("%+v", c)
	}
}
