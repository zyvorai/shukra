package state

import (
	"errors"
	"time"
)

var (
	// ErrActionNotFound: no action has that id.
	ErrActionNotFound = errors.New("no action with that id")
	// ErrActionNotPending: the action is not waiting for a decision.
	ErrActionNotPending = errors.New("the action is not waiting for a decision")
)

// Action is one thing a response decided to do to a VM: propose an isolation, carry it out, or refuse. It is a
// record of a decision, and the isolation it may lead to is separately in the isolate audit trail, under an
// actor that names the response and the action.
type Action struct {
	ID       string `json:"id"`
	VM       string `json:"vm"`
	Response string `json:"response"`
	Mode     string `json:"mode"` // propose or enforce
	DryRun   bool   `json:"dryRun,omitempty"`
	// Rule, Severity and Message are the detection that set it off.
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
	Created  time.Time `json:"created"`
	// Expires is when a proposal lapses if nobody decides.
	Expires time.Time `json:"expires,omitempty"`
	// Status is pending, executed, refused, rejected, expired, dry_run or released.
	Status    string    `json:"status"`
	Decided   time.Time `json:"decided,omitempty"`
	DecidedBy string    `json:"decidedBy,omitempty"`
	// Result says what the isolate request answered, or why it was not made.
	Result string `json:"result,omitempty"`
	// Guardrail names the guardrail that refused it.
	Guardrail string    `json:"guardrail,omitempty"`
	ReleaseAt time.Time `json:"releaseAt,omitempty"`
	Released  time.Time `json:"released,omitempty"`
	KeyID     string    `json:"keyId,omitempty"`
	Role      string    `json:"role,omitempty"`
	Label     string    `json:"label,omitempty"`
	Remote    string    `json:"remote,omitempty"`
	RequestID string    `json:"requestId,omitempty"`
	Op        string    `json:"op,omitempty"`
}

// ActionsView is what the API needs of the response engine. The engine implements it.
type ActionsView interface {
	// Enabled says whether the rules file has any responses.
	Enabled() bool
	// List is the actions, newest first: only those still waiting for a person, or all of them.
	List(all bool) []Action
	Approve(id, actor string) (Action, error)
	Reject(id, actor string) (Action, error)
	// Bundle is the incident bundle captured when the action was made, or false.
	Bundle(id string) ([]byte, bool)
	// Counts is how many actions there are in each status.
	Counts() map[string]int
	// Modes is how many responses are configured to propose, to enforce, and to only try out (dry run).
	Modes() (propose, enforce, dryRun int)
}

// SetActions gives the state its view of the response engine.
func (s *State) SetActions(v ActionsView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions = v
}

// Actions is the view, or nil when there is none.
func (s *State) Actions() ActionsView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.actions
}
