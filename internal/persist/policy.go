package persist

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/zyvorai/shukra/internal/policy"
)

const policyFile = "policies.json"

// Policies keeps the egress policies across restarts, and implements policy.Store. The file is private: it
// names VMs and the networks each may reach. It is rewritten whole, atomically and synced, on every change,
// because the kernel keeps enforcing without the daemon and the record must never be behind it.
type Policies struct{ path string }

type policyDoc struct {
	Version  int             `json:"version"`
	Policies []policy.Policy `json:"policies"`
}

// OpenPolicies returns the store under dir and what it holds. A file that cannot be read is set aside as
// policies.json.corrupt and the store starts empty, loudly: the taps the kernel still applies a policy on then
// show as orphans in the doctor, where a person can look at them, instead of the daemon guessing.
func OpenPolicies(dir string) (*Policies, []policy.Policy, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	p := &Policies{path: filepath.Join(dir, policyFile)}
	b, err := os.ReadFile(p.path)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var doc policyDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc.Version != 1 {
		aside := p.path + ".corrupt"
		log.Printf("persist: %s cannot be read (%v): setting it aside as %s and starting with no policies. A tap that is still enforcing one will be reported by shukractl doctor", p.path, err, aside)
		_ = os.Rename(p.path, aside)
		return p, nil, nil
	}
	return p, doc.Policies, nil
}

// Save implements policy.Store.
func (p *Policies) Save(ps []policy.Policy) error {
	if ps == nil {
		ps = []policy.Policy{}
	}
	return WriteJSON(p.path, policyDoc{Version: 1, Policies: ps})
}
