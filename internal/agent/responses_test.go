package agent

import (
	"os"
	"testing"

	"github.com/zyvorai/shukra/internal/response"
	"github.com/zyvorai/shukra/internal/state"
)

type nullStore struct{}

func (nullStore) Append(state.Action) error        { return nil }
func (nullStore) SaveBundle(string, []byte) error  { return nil }
func (nullStore) LoadBundle(string) ([]byte, bool) { return nil, false }

const oneResponse = "responses:\n  - name: ask\n    rules: [crypto-pool]\n    action: isolate\n"

func responseAgent(t *testing.T, yaml string) (*Agent, *state.State, *response.Engine) {
	t.Helper()
	ag, st := newTapAgent(t, yaml)
	e := response.New(st, nullStore{})
	ag.SetResponses(e)
	return ag, st, e
}

func TestTheAgentGivesTheEngineTheRulesNowAndTheStateTheEngine(t *testing.T) {
	_, st, e := responseAgent(t, oneResponse)
	if !e.Enabled() {
		t.Fatal("the rules in force at start were not applied")
	}
	if v := st.Actions(); v == nil || !v.Enabled() {
		t.Fatal("the API reads actions from the state, which must know the engine")
	}
}

func TestReloadingTheRulesChangesTheResponsesAndRemovingTheSectionTurnsThemOff(t *testing.T) {
	ag, _, e := responseAgent(t, oneResponse)
	p, en, d := e.Modes()
	if p != 1 || en != 0 || d != 0 {
		t.Fatalf("%d %d %d", p, en, d)
	}
	if err := os.WriteFile(ag.watchPath, []byte(oneResponse+"  - name: try\n    action: isolate\n    dry_run: true\n    min_severity: high\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	if p, en, d = e.Modes(); p != 1 || en != 0 || d != 1 {
		t.Fatalf("a reload must apply the new responses: %d %d %d", p, en, d)
	}
	if err := os.WriteFile(ag.watchPath, []byte("suppress: 5m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	if e.Enabled() {
		t.Fatal("removing the section must turn responses off")
	}
}

func TestABadResponsesSectionKeepsTheResponsesThatWereInForce(t *testing.T) {
	ag, _, e := responseAgent(t, oneResponse)
	// enforce must name the rules it answers.
	if err := os.WriteFile(ag.watchPath, []byte("responses:\n  - name: wide\n    action: isolate\n    mode: enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err == nil {
		t.Fatal("an enforcing response that answers everything was accepted")
	}
	if p, _, _ := e.Modes(); p != 1 || !e.Enabled() {
		t.Fatal("the previous responses must stay in force")
	}
}

func TestAnAgentWithoutAnEngineReloadsAsBefore(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	ag.SetResponses(nil)
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	if st.Actions() != nil {
		t.Fatal("no engine, no actions view")
	}
}
