package agent

import "github.com/zyvorai/shukra/internal/response"

// SetResponses gives the agent the response engine, and gives the engine the rules in force now and after every
// reload. A bad reload leaves the previous responses in force, like every other rule.
func (a *Agent) SetResponses(e *response.Engine) {
	a.responses = e
	if e != nil {
		e.SetConfig(a.cfg.Load())
		a.State.SetActions(e)
	}
}
