package state

import (
	"errors"
	"time"
)

var (
	// ErrPolicyNotFound: no VM, or no policy, with that name.
	ErrPolicyNotFound = errors.New("not found")
	// ErrPolicyBad: the request itself is wrong.
	ErrPolicyBad = errors.New("bad request")
	// ErrPolicyRefused: the request is well formed and is refused, with the reason in the error.
	ErrPolicyRefused = errors.New("refused")
)

// PolicyRequest is a request to put a VM under an egress policy, or to change or lift one.
type PolicyRequest struct {
	// Mode is "off", "audit" or "enforce".
	Mode string `json:"mode"`
	// Allow is the networks the VM may start connections to. FromBaseline takes them from what the VM has
	// been seen to talk to instead. With neither, a VM that already has a policy keeps its list.
	Allow        []string `json:"allow,omitempty"`
	FromBaseline bool     `json:"fromBaseline,omitempty"`
	// Confirm is how long an enforcing policy stands before it goes back to what it replaced, unless someone
	// confirms it. Permanent says there is no such timer. One of the two is required to enforce.
	Confirm   string `json:"confirm,omitempty"`
	Permanent bool   `json:"permanent,omitempty"`
}

// PolicyTap is what a VM's policy has done on one of its taps.
type PolicyTap struct {
	Tap string `json:"tap"`
	// Kernel is the mode the program is in on this tap, which is the policy's unless something is wrong.
	Kernel string `json:"kernel"`
	// Checked is how many new connections and datagrams were judged; Audit is how many would have been
	// dropped, and Dropped how many were.
	Checked      uint64 `json:"checked"`
	AuditPkts    uint64 `json:"auditPackets"`
	AuditBytes   uint64 `json:"auditBytes"`
	DroppedPkts  uint64 `json:"droppedPackets"`
	DroppedBytes uint64 `json:"droppedBytes"`
}

// PolicyRevert says an enforcing policy is waiting to be confirmed.
type PolicyRevert struct {
	Until time.Time `json:"until"`
	// To is what the VM goes back to if nobody confirms: "off", or the mode and networks that came before.
	To string `json:"to"`
}

// PolicyRow is one VM's egress policy and what it has done.
type PolicyRow struct {
	VM        string    `json:"vm"`
	Mode      string    `json:"mode"`
	Allow     []string  `json:"allow"`
	Source    string    `json:"source"` // baseline or manual
	By        string    `json:"by,omitempty"`
	Applied   time.Time `json:"applied"`
	KeyID     string    `json:"keyId,omitempty"`
	Role      string    `json:"role,omitempty"`
	Label     string    `json:"label,omitempty"`
	Remote    string    `json:"remote,omitempty"`
	RequestID string    `json:"requestId,omitempty"`
	Op        string    `json:"op,omitempty"`
	// Present says the VM is in the current scan. A policy for a VM that is not running is kept.
	Present bool          `json:"present"`
	Revert  *PolicyRevert `json:"revert,omitempty"`
	Taps    []PolicyTap   `json:"taps"`
	// Problem is set when the kernel is not doing what the policy says.
	Problem string `json:"problem,omitempty"`
}

// PolicyProposal is the egress policy a VM's learned baseline suggests, and how it differs from the one it has.
type PolicyProposal struct {
	VM string `json:"vm"`
	// Learning says the VM is still inside its baseline's learning period, so the list may be incomplete.
	Learning bool     `json:"learning"`
	Allow    []string `json:"allow"`
	// Current is the list the VM's policy has now, if it has one, and Added and Removed are how Allow differs.
	Current []string `json:"current"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Note    string   `json:"note,omitempty"`
}

// PolicyOrphan is a tap the kernel is applying an egress policy on, with no record of it: the record was
// lost, or something else set it. It is enforcing (or auditing) what nobody can say.
type PolicyOrphan struct {
	VM   string `json:"vm"`
	Tap  string `json:"tap"`
	Mode string `json:"mode"`
}

// PolicyView is what the API, the doctor and /metrics need of the egress policy engine.
type PolicyView interface {
	// List is every VM's policy, sorted by VM name.
	List() []PolicyRow
	Get(vm string) (PolicyRow, bool)
	// Learn proposes a policy from the VM's learned baseline.
	Learn(vm string) (PolicyProposal, error)
	Apply(vm string, req PolicyRequest, actor string) (PolicyRow, error)
	// Confirm makes an enforcing policy stay, cancelling the timer that would have reverted it.
	Confirm(vm, actor string) (PolicyRow, error)
	// Remove lifts a VM's policy, whether or not there is a record of one.
	Remove(vm, actor string) (PolicyRow, error)
	Orphans() []PolicyOrphan
	// Persisted says whether policies survive a restart of the daemon (there is a data directory).
	Persisted() bool
}

// SetPolicy gives the state its view of the egress policy engine.
func (s *State) SetPolicy(v PolicyView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = v
}

// Policy is the egress policy view, or nil when there is no engine.
func (s *State) Policy() PolicyView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}
