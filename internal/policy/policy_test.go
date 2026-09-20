package policy

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/observe"
	"github.com/zyvorai/shukra/internal/state"
)

type fakeKernel struct {
	mu         sync.Mutex
	avail      bool
	canEnforce bool
	modes      map[string]uint8
	lists      map[string][]netip.Prefix
	fail       map[string]error
	sets       []string
	stats      []observe.EgressCounters
	leak, once bool // a failing Set leaves its list behind; a failure happens once
}

func newKernel() *fakeKernel {
	return &fakeKernel{avail: true, canEnforce: true, modes: map[string]uint8{}, lists: map[string][]netip.Prefix{}, fail: map[string]error{}}
}

func (k *fakeKernel) Available() (bool, string) {
	if !k.avail {
		return false, "not loaded"
	}
	return true, ""
}
func (k *fakeKernel) CanEnforce() (bool, string) {
	if !k.canEnforce {
		return false, "no management allow list is configured"
	}
	return true, ""
}
func (k *fakeKernel) Set(tap string, mode uint8, p []netip.Prefix) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.fail[tap]; err != nil {
		if k.leak {
			k.lists[tap] = p // a map that filled up part of the way: some of the list is in, the mode is not
		}
		if k.once {
			delete(k.fail, tap)
		}
		return err
	}
	k.modes[tap], k.lists[tap] = mode, p
	k.sets = append(k.sets, tap)
	return nil
}
func (k *fakeKernel) Mode(tap string) uint8 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.modes[tap]
}
func (k *fakeKernel) Stats() []observe.EgressCounters { return k.stats }
func (k *fakeKernel) setCount() int                   { k.mu.Lock(); defer k.mu.Unlock(); return len(k.sets) }

type memStore struct {
	saved [][]Policy
	err   error
}

func (m *memStore) Save(p []Policy) error {
	if m.err != nil {
		return m.err
	}
	m.saved = append(m.saved, append([]Policy(nil), p...))
	return nil
}
func (m *memStore) last() []Policy {
	if len(m.saved) == 0 {
		return nil
	}
	return m.saved[len(m.saved)-1]
}

// baselines is a state.BaselineView over a real store.
type baselines struct {
	s  *baseline.Store
	on bool
}

func (b baselines) Enabled() bool                                       { return b.on }
func (b baselines) Persisted() bool                                     { return true }
func (b baselines) Options() baseline.Options                           { return b.s.Options() }
func (b baselines) Forget(vm string) bool                               { return b.s.Forget(vm) }
func (b baselines) Items(vm string, n int) []baseline.Learned           { return b.s.Items(vm, n) }
func (b baselines) Status(vm string, now time.Time) []baseline.VMStatus { return b.s.Status(vm, now) }

type world struct {
	e     *Engine
	st    *state.State
	k     *fakeKernel
	store *memStore
	now   time.Time
	bl    *baseline.Store
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{st: state.New("node-07"), k: newKernel(), store: &memStore{}, now: time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)}
	w.st.SetVMs([]identity.VM{
		{Name: "web", UUID: "u1", Runtime: "qemu", PID: 100, Taps: []string{"tapweb"}},
		{Name: "db", UUID: "u2", Runtime: "qemu", PID: 200, Taps: []string{"tapdb1", "tapdb2"}},
		{Name: "usernet", UUID: "u3", Runtime: "qemu", PID: 300},
	})
	w.e = New(w.st, w.k, w.store)
	w.e.now = func() time.Time { return w.now }
	w.bl = baseline.NewStore(baseline.DefaultOptions())
	w.st.SetBaselines(baselines{s: w.bl, on: true})
	return w
}

func (w *world) audit(t *testing.T, vm string, allow ...string) state.PolicyRow {
	t.Helper()
	row, err := w.e.Apply(vm, state.PolicyRequest{Mode: "audit", Allow: allow}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func (w *world) detections(rule string) []event.Event {
	var out []event.Event
	for _, e := range w.st.Events("") {
		if e.Kind == event.KindDetection && e.Rule == rule {
			out = append(out, e)
		}
	}
	return out
}

func kernelList(k *fakeKernel, tap string) []string {
	var out []string
	for _, p := range k.lists[tap] {
		out = append(out, p.String())
	}
	return out
}

func TestAuditPutsEveryTapUnderTheListAndNeedsNoManagementFloor(t *testing.T) {
	w := newWorld(t)
	w.k.canEnforce = false // audit does not need it
	row := w.audit(t, "db", "203.0.113.9/24", "2001:db8::1", "198.51.100.7")
	if row.Mode != "audit" || row.Source != "manual" || row.By != "tester" || !row.Present || len(row.Taps) != 2 {
		t.Fatalf("%+v", row)
	}
	want := []string{"198.51.100.7/32", "203.0.113.0/24", "2001:db8::1/128"}
	if !reflect.DeepEqual(row.Allow, want) {
		t.Fatalf("the list is canonical and sorted: %v", row.Allow)
	}
	for _, tap := range []string{"tapdb1", "tapdb2"} {
		if w.k.Mode(tap) != 1 || !reflect.DeepEqual(kernelList(w.k, tap), want) {
			t.Fatalf("%s: mode %d list %v", tap, w.k.Mode(tap), kernelList(w.k, tap))
		}
	}
	if w.k.Mode("tapweb") != 0 {
		t.Fatal("another VM's tap was touched")
	}
	if p := w.store.last(); len(p) != 1 || p[0].VM != "db" || p[0].Mode != Audit {
		t.Fatalf("saved %+v", p)
	}
	if d := w.detections("policy-applied"); len(d) != 1 || d[0].Severity != "low" || d[0].VM.Name != "db" || !strings.Contains(d[0].Message, "is auditing an egress policy of 3 networks") {
		t.Fatalf("%+v", d)
	}
}

func TestEnforcingIsRefusedUnlessEverySafetyIsInPlace(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(w *world)
		req   state.PolicyRequest
		want  error
		text  string
	}{
		"no management floor":               {func(w *world) { w.k.canEnforce = false }, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "5m"}, state.ErrPolicyRefused, "management allow list"},
		"no record that survives a restart": {func(w *world) { w.e.store = nil }, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "5m"}, state.ErrPolicyRefused, "-data-dir"},
		"an empty list":                     {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"  "}, Confirm: "5m"}, state.ErrPolicyRefused, "that is what isolate is for"},
		"no list to enforce":                {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Confirm: "5m"}, state.ErrPolicyBad, "no list of networks"},
		"neither a timer nor permanent":     {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}}, state.ErrPolicyBad, "--confirm"},
		"a timer and permanent":             {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "5m", Permanent: true}, state.ErrPolicyBad, "not both"},
		"a timer too short":                 {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "5s"}, state.ErrPolicyBad, "30s"},
		"a timer too long":                  {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "48h"}, state.ErrPolicyBad, "24h"},
		"a timer that is not one":           {func(w *world) {}, state.PolicyRequest{Mode: "enforce", Allow: []string{"10.0.0.0/8"}, Confirm: "soon"}, state.ErrPolicyBad, "soon"},
		"a mode nobody knows":               {func(w *world) {}, state.PolicyRequest{Mode: "block", Allow: []string{"10.0.0.0/8"}}, state.ErrPolicyBad, "off, audit or enforce"},
		"the program is not loaded":         {func(w *world) { w.k.avail = false }, state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, state.ErrPolicyRefused, "not loaded"},
		"a network that is not one":         {func(w *world) {}, state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/33"}}, state.ErrPolicyBad, "not a network"},
		"an address that is not one":        {func(w *world) {}, state.PolicyRequest{Mode: "audit", Allow: []string{"web.example.com"}}, state.ErrPolicyBad, "not an address"},
		"no list at all":                    {func(w *world) {}, state.PolicyRequest{Mode: "audit"}, state.ErrPolicyBad, "--allow"},
	} {
		w := newWorld(t)
		tc.setup(w)
		_, err := w.e.Apply("web", tc.req, "tester")
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
			t.Fatalf("%s: %v, want %v containing %q", name, err, tc.want, tc.text)
		}
		if w.k.setCount() != 0 || len(w.e.pol) != 0 || len(w.store.saved) != 0 {
			t.Fatalf("%s: a refused request changed something: %d sets, %d policies, %d saves", name, w.k.setCount(), len(w.e.pol), len(w.store.saved))
		}
	}
}

func TestAVMThatCannotHaveAPolicyIsSaidSo(t *testing.T) {
	w := newWorld(t)
	if _, err := w.e.Apply("nobody", state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, "t"); !errors.Is(err, state.ErrPolicyNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := w.e.Apply("usernet", state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, "t"); !errors.Is(err, state.ErrPolicyRefused) || !strings.Contains(err.Error(), "no tap") {
		t.Fatalf("%v", err)
	}
}

func TestTooLongAListIsRefused(t *testing.T) {
	w := newWorld(t)
	var many []string
	for i := 0; i < MaxAllow+1; i++ {
		many = append(many, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String()+"/24")
	}
	if _, err := w.e.Apply("web", state.PolicyRequest{Mode: "audit", Allow: many}, "t"); !errors.Is(err, state.ErrPolicyBad) || !strings.Contains(err.Error(), "1024") {
		t.Fatalf("%v", err)
	}
}

func TestEnforcingWaitsForAConfirmationAndGoesBackToNothingWithoutOne(t *testing.T) {
	w := newWorld(t)
	row, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Confirm: "5m"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if row.Mode != "enforce" || w.k.Mode("tapweb") != 2 || row.Revert == nil || row.Revert.To != "no policy" || !row.Revert.Until.Equal(w.now.Add(5*time.Minute)) {
		t.Fatalf("%+v mode %d", row, w.k.Mode("tapweb"))
	}
	if d := w.detections("policy-applied"); len(d) != 1 || d[0].Severity != "medium" || !strings.Contains(d[0].Message, "now enforcing") || !strings.Contains(d[0].Message, "shukractl policy confirm web") {
		t.Fatalf("%+v", d)
	}
	w.now = w.now.Add(4*time.Minute + 59*time.Second)
	w.e.Reconcile()
	if w.k.Mode("tapweb") != 2 || len(w.e.pol) != 1 {
		t.Fatal("it reverted before its time")
	}
	w.now = w.now.Add(time.Second)
	w.e.Reconcile()
	if w.k.Mode("tapweb") != 0 || len(w.e.pol) != 0 || len(w.store.last()) != 0 {
		t.Fatalf("unconfirmed, it must be gone: mode %d, %d policies, saved %+v", w.k.Mode("tapweb"), len(w.e.pol), w.store.last())
	}
	if d := w.detections("policy-reverted"); len(d) != 1 || d[0].Severity != "medium" || !strings.Contains(d[0].Message, "not confirmed in time and has been removed") {
		t.Fatalf("%+v", d)
	}
}

func TestEnforcingOverAnAuditGoesBackToTheAuditWithItsList(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "203.0.113.0/24", "198.51.100.0/24")
	row, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Confirm: "1m"}, "alice")
	if err != nil || row.Revert == nil || row.Revert.To != "audit with 2 networks" {
		t.Fatalf("%v %+v", err, row.Revert)
	}
	w.now = w.now.Add(time.Minute)
	w.e.Reconcile()
	p := w.e.pol["web"]
	if p == nil || p.Mode != Audit || len(p.Allow) != 2 || p.Revert != nil || w.k.Mode("tapweb") != 1 || len(w.k.lists["tapweb"]) != 2 {
		t.Fatalf("%+v mode %d list %v", p, w.k.Mode("tapweb"), kernelList(w.k, "tapweb"))
	}
	if d := w.detections("policy-reverted"); len(d) != 1 || !strings.Contains(d[0].Message, "gone back to audit with 2 networks") {
		t.Fatalf("%+v", d)
	}
}

func TestChangingAnUnconfirmedPolicyStillGoesBackToWhatCameBeforeAllOfIt(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "198.51.100.0/24")
	if _, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Confirm: "10m"}, "a"); err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(time.Minute)
	row, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24", "192.0.2.0/24"}, Confirm: "10m"}, "a")
	if err != nil || row.Revert == nil || row.Revert.To != "audit with 1 networks" {
		t.Fatalf("what it goes back to is the audit, not the first enforce: %v %+v", err, row.Revert)
	}
	if !row.Revert.Until.Equal(w.now.Add(10 * time.Minute)) {
		t.Fatalf("a new timer: %v", row.Revert.Until)
	}
}

func TestConfirmingKeepsThePolicyForGood(t *testing.T) {
	w := newWorld(t)
	if _, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Confirm: "1m"}, "a"); err != nil {
		t.Fatal(err)
	}
	row, err := w.e.Confirm("web", "bob")
	if err != nil || row.Revert != nil || row.Mode != "enforce" {
		t.Fatalf("%v %+v", err, row)
	}
	if p := w.store.last(); len(p) != 1 || p[0].Revert != nil {
		t.Fatalf("the confirmation is saved: %+v", p)
	}
	w.now = w.now.Add(24 * time.Hour)
	w.e.Reconcile()
	if w.k.Mode("tapweb") != 2 {
		t.Fatal("a confirmed policy went away")
	}
	if d := w.detections("policy-confirmed"); len(d) != 1 || !strings.Contains(d[0].Message, "confirmed by bob") {
		t.Fatalf("%+v", d)
	}
	if _, err := w.e.Confirm("web", "bob"); !errors.Is(err, state.ErrPolicyRefused) {
		t.Fatalf("nothing waits: %v", err)
	}
	if _, err := w.e.Confirm("db", "bob"); !errors.Is(err, state.ErrPolicyNotFound) {
		t.Fatalf("no policy: %v", err)
	}
}

func TestAPermanentEnforceHasNoTimerAndAConfirmationThatCannotBeSavedDoesNotTakeEffect(t *testing.T) {
	w := newWorld(t)
	row, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Permanent: true}, "a")
	if err != nil || row.Revert != nil || w.e.pol["web"].Revert != nil {
		t.Fatalf("%v %+v", err, row)
	}
	w2 := newWorld(t)
	if _, err := w2.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Confirm: "1m"}, "a"); err != nil {
		t.Fatal(err)
	}
	w2.store.err = errors.New("disk full")
	if _, err := w2.e.Confirm("web", "b"); err == nil || w2.e.pol["web"].Revert == nil {
		t.Fatalf("a confirmation nobody could save must leave the timer running: %v", err)
	}
}

func TestARecordThatCannotBeSavedMeansNothingIsApplied(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "198.51.100.0/24")
	sets := w.k.setCount()
	w.store.err = errors.New("disk full")
	_, err := w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Allow: []string{"203.0.113.0/24"}, Permanent: true}, "a")
	if err == nil || !strings.Contains(err.Error(), "not saved, so it was not applied") {
		t.Fatalf("%v", err)
	}
	if w.k.setCount() != sets || w.k.Mode("tapweb") != 1 || w.e.pol["web"].Mode != Audit || w.e.pol["web"].Allow[0] != "198.51.100.0/24" {
		t.Fatal("the failed change left a trace")
	}
}

func TestAChangeNoTapTookIsPutBack(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "db", "198.51.100.0/24")
	w.k.fail["tapdb1"], w.k.fail["tapdb2"] = errors.New("map full"), errors.New("map full")
	_, err := w.e.Apply("db", state.PolicyRequest{Mode: "audit", Allow: []string{"203.0.113.0/24"}}, "a")
	if err == nil || !strings.Contains(err.Error(), "did not take the policy") {
		t.Fatalf("%v", err)
	}
	if p := w.e.pol["db"]; p == nil || p.Allow[0] != "198.51.100.0/24" {
		t.Fatalf("the record must be what it was: %+v", p)
	}
	if last := w.store.last(); len(last) != 1 || last[0].Allow[0] != "198.51.100.0/24" {
		t.Fatalf("and so must what is saved: %+v", last)
	}
	// with no policy before it, a failed first one leaves none
	w2 := newWorld(t)
	w2.k.fail["tapweb"] = errors.New("map full")
	if _, err := w2.e.Apply("web", state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, "a"); err == nil || len(w2.e.pol) != 0 || len(w2.store.last()) != 0 {
		t.Fatalf("%v %d", err, len(w2.e.pol))
	}
}

func TestATapThatDidNotTakeItIsReportedAndTheOthersKeepIt(t *testing.T) {
	w := newWorld(t)
	w.k.fail["tapdb2"] = errors.New("gone")
	row, err := w.e.Apply("db", state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, "a")
	if err != nil || !strings.Contains(row.Problem, "some taps did not take it") || !strings.Contains(row.Problem, "tapdb2") || w.k.Mode("tapdb1") != 1 {
		t.Fatalf("%v %+v", err, row)
	}
}

func TestRemovingPutsTheKernelRightWhetherOrNotThereIsARecord(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "db", "10.0.0.0/8")
	row, err := w.e.Remove("db", "carol")
	if err != nil || row.Mode != "off" || w.k.Mode("tapdb1") != 0 || w.k.Mode("tapdb2") != 0 || len(w.e.pol) != 0 || len(w.store.last()) != 0 {
		t.Fatalf("%v %+v", err, row)
	}
	if d := w.detections("policy-removed"); len(d) != 1 || !strings.Contains(d[0].Message, "removed by carol") {
		t.Fatalf("%+v", d)
	}
	// the record was lost but the kernel still enforces: remove clears it
	w.k.modes["tapweb"] = 2
	if row, err = w.e.Remove("web", "carol"); err != nil || w.k.Mode("tapweb") != 0 {
		t.Fatalf("%v %+v", err, row)
	}
	if _, err = w.e.Remove("web", "carol"); !errors.Is(err, state.ErrPolicyNotFound) {
		t.Fatalf("nothing to remove: %v", err)
	}
	// mode off is the same as remove
	w.audit(t, "web", "10.0.0.0/8")
	if _, err = w.e.Apply("web", state.PolicyRequest{Mode: "off"}, "carol"); err != nil || w.k.Mode("tapweb") != 0 {
		t.Fatalf("%v", err)
	}
}

func TestReconcileMakesTheKernelMatchTheRecordAndLeavesWhatMatchesAlone(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "db", "10.0.0.0/8")
	sets := w.k.setCount()
	w.e.Reconcile()
	if w.k.setCount() != sets {
		t.Fatal("a tap that already matches was set again")
	}
	// the VM came back with a new tap: the kernel has nothing on it
	w.k.modes["tapdb2"] = 0
	w.e.Reconcile()
	if w.k.Mode("tapdb2") != 1 || w.k.setCount() != sets+1 {
		t.Fatalf("mode %d, %d sets", w.k.Mode("tapdb2"), w.k.setCount())
	}
	// the kernel was set to something else
	w.k.modes["tapdb1"] = 2
	w.e.Reconcile()
	if w.k.Mode("tapdb1") != 1 {
		t.Fatal("the record wins")
	}
}

func TestAPolicyForAVMThatIsNotRunningIsKeptAndSayssoAndTheTapsOfOthersAreNotTouched(t *testing.T) {
	w := newWorld(t)
	w.e.Restore([]Policy{{VM: "gone", Mode: Audit, Allow: []string{"10.0.0.0/8"}, Source: "manual", Applied: w.now}})
	w.e.Reconcile()
	rows := w.e.List()
	if len(rows) != 1 || rows[0].VM != "gone" || rows[0].Present || len(rows[0].Taps) != 0 || rows[0].Problem != "" {
		t.Fatalf("%+v", rows)
	}
	if w.k.setCount() != 0 {
		t.Fatal("nothing was set")
	}
}

func TestATapWithAPolicyNobodyRecordedIsAnOrphanAndIsNotTouched(t *testing.T) {
	w := newWorld(t)
	w.k.modes["tapweb"] = 2
	w.e.Reconcile()
	if w.k.Mode("tapweb") != 2 || w.k.setCount() != 0 {
		t.Fatal("reconcile must not guess about a policy it has no record of")
	}
	o := w.e.Orphans()
	if len(o) != 1 || o[0].VM != "web" || o[0].Tap != "tapweb" || o[0].Mode != "enforce" {
		t.Fatalf("%+v", o)
	}
	w.audit(t, "web", "10.0.0.0/8")
	if len(w.e.Orphans()) != 0 {
		t.Fatal("once recorded it is not an orphan")
	}
}

func TestRestoredPoliciesAreAppliedAndAnExpiredTimerRevertsOnTheFirstPass(t *testing.T) {
	w := newWorld(t)
	past := w.now.Add(-time.Hour)
	w.e.Restore([]Policy{
		{VM: "web", Mode: Enforce, Allow: []string{"203.0.113.0/24"}, Source: "manual", Applied: past, Revert: &Revert{Until: past.Add(5 * time.Minute), Mode: Off}},
		{VM: "db", Mode: Enforce, Allow: []string{"198.51.100.0/24"}, Source: "manual", Applied: past},
		{VM: "bad", Mode: "block", Allow: []string{"10.0.0.0/8"}},
		{VM: "worse", Mode: Audit, Allow: []string{"nonsense"}},
		{Mode: Audit, Allow: []string{"10.0.0.0/8"}},
	})
	if len(w.e.pol) != 2 {
		t.Fatalf("what cannot be trusted is dropped: %d", len(w.e.pol))
	}
	w.k.modes["tapweb"] = 2 // the kernel kept enforcing while the daemon was down
	w.e.Reconcile()
	if w.k.Mode("tapweb") != 0 || w.e.pol["web"] != nil {
		t.Fatal("the timer ran out while the daemon was down: web must be released now")
	}
	if w.k.Mode("tapdb1") != 2 || w.k.Mode("tapdb2") != 2 || len(w.k.lists["tapdb1"]) != 1 {
		t.Fatal("db's confirmed policy is applied to both its taps")
	}
}

func TestTheRowSaysWhenTheKernelIsNotDoingWhatThePolicySays(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "10.0.0.0/8")
	w.k.stats = []observe.EgressCounters{{Tap: "tapweb", Mode: 1, Checked: 40, AuditPkts: 7, AuditBytes: 700, DropPkts: 3, DropBytes: 300}, {Tap: "tapdb1", Checked: 999}}
	row, ok := w.e.Get("web")
	if !ok || row.Problem != "" || len(row.Taps) != 1 {
		t.Fatalf("%+v", row)
	}
	if tp := row.Taps[0]; tp.Tap != "tapweb" || tp.Kernel != "audit" || tp.Checked != 40 || tp.AuditPkts != 7 || tp.AuditBytes != 700 || tp.DroppedPkts != 3 || tp.DroppedBytes != 300 {
		t.Fatalf("the counters of this tap, and only this tap: %+v", tp)
	}
	w.k.modes["tapweb"] = 0
	row, _ = w.e.Get("web")
	if !strings.Contains(row.Problem, "tapweb in mode off, and the policy says audit") {
		t.Fatalf("%q", row.Problem)
	}
	if _, ok := w.e.Get("db"); ok {
		t.Fatal("db has no policy")
	}
}

func TestTheListOfPoliciesIsSortedAndPersistedSaysWhetherThereIsARecord(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "10.0.0.0/8")
	w.audit(t, "db", "10.0.0.0/8")
	rows := w.e.List()
	if len(rows) != 2 || rows[0].VM != "db" || rows[1].VM != "web" {
		t.Fatalf("%+v", rows)
	}
	if !w.e.Persisted() {
		t.Fatal("a store means persisted")
	}
	if New(w.st, w.k, nil).Persisted() {
		t.Fatal("no store, not persisted")
	}
}

func learn(w *world, vm string, items ...string) {
	for _, it := range items {
		w.bl.Observe(vm, baseline.Destination, it, w.now)
	}
}

func TestLearnProposesTheDestinationsTheVMHasBeenSeenAt(t *testing.T) {
	w := newWorld(t)
	learn(w, "web", "203.0.113.0/24", "198.51.100.0/24", "2001:db8:5::/64")
	w.bl.Observe("web", baseline.DNSSuffix, "example.com", w.now)
	w.bl.Observe("web", baseline.InboundPeer, "192.0.2.0/24", w.now)
	prop, err := w.e.Learn("web")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prop.Allow, []string{"198.51.100.0/24", "203.0.113.0/24", "2001:db8:5::/64"}) {
		t.Fatalf("only destinations, sorted: %v", prop.Allow)
	}
	if !prop.Learning || !strings.Contains(prop.Note, "still inside its baseline's learning period") {
		t.Fatalf("a VM seen a moment ago is still learning: %+v", prop)
	}
	if len(prop.Current) != 0 || len(prop.Removed) != 0 || len(prop.Added) != 3 {
		t.Fatalf("%+v", prop)
	}
}

func TestLearnSaysHowTheProposalDiffersFromThePolicyTheVMHas(t *testing.T) {
	w := newWorld(t)
	learn(w, "web", "203.0.113.0/24", "198.51.100.0/24")
	w.audit(t, "web", "203.0.113.0/24", "192.0.2.0/24")
	prop, err := w.e.Learn("web")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prop.Current, []string{"192.0.2.0/24", "203.0.113.0/24"}) || !reflect.DeepEqual(prop.Added, []string{"198.51.100.0/24"}) || !reflect.DeepEqual(prop.Removed, []string{"192.0.2.0/24"}) {
		t.Fatalf("%+v", prop)
	}
}

func TestLearnIsRefusedWithoutBaselinesAndForAVMTheyHaveNotSeen(t *testing.T) {
	w := newWorld(t)
	w.st.SetBaselines(baselines{s: w.bl, on: false})
	if _, err := w.e.Learn("web"); !errors.Is(err, state.ErrPolicyRefused) || !strings.Contains(err.Error(), "baselines") {
		t.Fatalf("%v", err)
	}
	w.st.SetBaselines(nil)
	if _, err := w.e.Learn("web"); !errors.Is(err, state.ErrPolicyRefused) {
		t.Fatalf("%v", err)
	}
	w.st.SetBaselines(baselines{s: w.bl, on: true})
	if _, err := w.e.Learn("stranger"); !errors.Is(err, state.ErrPolicyNotFound) {
		t.Fatalf("%v", err)
	}
	w.bl.Observe("web", baseline.DNSSuffix, "example.com", w.now) // seen, but never at a destination
	prop, err := w.e.Learn("web")
	if err != nil || len(prop.Allow) != 0 || !strings.Contains(prop.Note, "learning period") {
		t.Fatalf("%v %+v", err, prop)
	}
}

func TestTheListComesFromWhatWasGivenThenTheBaselineThenWhatTheVMHas(t *testing.T) {
	w := newWorld(t)
	learn(w, "web", "203.0.113.0/24")
	row, err := w.e.Apply("web", state.PolicyRequest{Mode: "audit", FromBaseline: true}, "a")
	if err != nil || row.Source != "baseline" || !reflect.DeepEqual(row.Allow, []string{"203.0.113.0/24"}) {
		t.Fatalf("%v %+v", err, row)
	}
	// a list that was given wins over the baseline
	row, _ = w.e.Apply("web", state.PolicyRequest{Mode: "audit", FromBaseline: true, Allow: []string{"10.0.0.0/8"}}, "a")
	if row.Source != "manual" || !reflect.DeepEqual(row.Allow, []string{"10.0.0.0/8"}) {
		t.Fatalf("%+v", row)
	}
	// with neither, a VM keeps its list, and its source
	row, err = w.e.Apply("web", state.PolicyRequest{Mode: "enforce", Confirm: "1m"}, "a")
	if err != nil || row.Source != "manual" || !reflect.DeepEqual(row.Allow, []string{"10.0.0.0/8"}) {
		t.Fatalf("%v %+v", err, row)
	}
	// an empty baseline cannot become an enforced policy
	learn(w, "db", "10.9.9.0/24")
	w.st.SetBaselines(baselines{s: baseline.NewStore(baseline.DefaultOptions()), on: true})
	if _, err = w.e.Apply("db", state.PolicyRequest{Mode: "audit", FromBaseline: true}, "a"); !errors.Is(err, state.ErrPolicyNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestAListIsCanonicalAndAnIPv4MappedNetworkIsIPv4(t *testing.T) {
	ps, err := parseAllow([]string{"203.0.113.9/24", "203.0.113.200/24", "198.51.100.7", "2001:db8::1", "::ffff:192.0.2.0/120", " ", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.7/32", "203.0.113.0/24", "2001:db8::1/128"}
	if got := prefixStrings(ps); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"::ffff:0.0.0.0/64", "1.2.3.4/40", "example.com", "1.2.3", "/8"} {
		if _, err := parseAllow([]string{bad}); !errors.Is(err, state.ErrPolicyBad) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestAFailedChangeLeavesNoPartOfTheNewListInTheKernel(t *testing.T) {
	w := newWorld(t)
	w.audit(t, "web", "198.51.100.0/24")
	w.k.leak, w.k.once = true, true
	w.k.fail["tapweb"] = errors.New("map full")
	if _, err := w.e.Apply("web", state.PolicyRequest{Mode: "audit", Allow: []string{"203.0.113.0/24", "192.0.2.0/24"}}, "a"); err == nil {
		t.Fatal("it should have failed")
	}
	if got := kernelList(w.k, "tapweb"); !reflect.DeepEqual(got, []string{"198.51.100.0/24"}) || w.k.Mode("tapweb") != 1 {
		t.Fatalf("the part of the new list that got in must be taken out again: %v mode %d", got, w.k.Mode("tapweb"))
	}
	// with no policy before it, a failed first one leaves the tap off
	w2 := newWorld(t)
	w2.k.leak, w2.k.once = true, true
	w2.k.fail["tapweb"] = errors.New("map full")
	if _, err := w2.e.Apply("web", state.PolicyRequest{Mode: "audit", Allow: []string{"10.0.0.0/8"}}, "a"); err == nil {
		t.Fatal("it should have failed")
	}
	if got := kernelList(w2.k, "tapweb"); len(got) != 0 || w2.k.Mode("tapweb") != 0 {
		t.Fatalf("%v mode %d", got, w2.k.Mode("tapweb"))
	}
}
