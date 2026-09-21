package state

import "strings"

// Caller is who made a mutating API call. Name is a free-form actor used by
// tests and by automatic responses ("auto:..."). A key id is a prefix of the
// SHA-256 of the bearer key, never the key.
type Caller struct {
	KeyID     string
	Role      string
	Label     string
	Remote    string
	RequestID string
	Op        string
	// Cause names the response action that asked for an isolation, as
	// "<response>:<id>" or just the id. It is set only on that path.
	Cause string
	Name  string
}

// Principal is what an audit record shows as who decided: the key id, and the
// client label in parentheses when one was sent. A caller with no key id is
// just Name (a test, or an automatic response).
func (c Caller) Principal() string {
	if c.KeyID == "" {
		if c.Name != "" {
			return c.Name
		}
		if c.Label != "" {
			return c.Label
		}
		return "api"
	}
	if c.Label != "" {
		return c.KeyID + " (" + c.Label + ")"
	}
	return c.KeyID
}

// EncodeActor is the string form the API passes through the existing actor
// parameters. ParseActor reverses it. A string that does not start with "key="
// is a plain name.
func EncodeActor(c Caller) string {
	if c.KeyID == "" {
		return c.Principal()
	}
	b := "key=" + c.KeyID + " role=" + c.Role + " op=" + c.Op
	if c.Label != "" {
		b += " label=" + c.Label
	}
	if c.Remote != "" {
		b += " remote=" + c.Remote
	}
	if c.RequestID != "" {
		b += " req=" + c.RequestID
	}
	return b
}

// ParseActor reads EncodeActor. Anything else is a plain name.
func ParseActor(s string) Caller {
	if !strings.HasPrefix(s, "key=") {
		return Caller{Name: s}
	}
	var c Caller
	for _, f := range strings.Fields(s) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "key":
			c.KeyID = v
		case "role":
			c.Role = v
		case "label":
			c.Label = v
		case "remote":
			c.Remote = v
		case "req":
			c.RequestID = v
		case "op":
			c.Op = v
		case "cause":
			c.Cause = v
		}
	}
	return c
}

// StampAudit copies a caller onto an isolation record. Actor is the principal,
// not the raw header.
func StampAudit(a *Audit, c Caller) {
	a.Actor = c.Principal()
	if c.Cause != "" {
		a.Actor += " (" + c.Cause + ")"
	}
	a.KeyID = c.KeyID
	a.Role = c.Role
	a.Label = c.Label
	a.Remote = c.Remote
	a.RequestID = c.RequestID
	if c.Op != "" {
		a.Op = c.Op
	}
}

// StampAction copies a caller onto a response decision.
func StampAction(a *Action, c Caller) {
	a.DecidedBy = c.Principal()
	a.KeyID = c.KeyID
	a.Role = c.Role
	a.Label = c.Label
	a.Remote = c.Remote
	a.RequestID = c.RequestID
	if c.Op != "" {
		a.Op = c.Op
	}
}
