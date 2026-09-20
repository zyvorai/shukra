package persist

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/policy"
)

func TestPoliciesAreKeptAndComeBackAsTheyWere(t *testing.T) {
	dir := t.TempDir()
	st, past, err := OpenPolicies(dir)
	if err != nil || len(past) != 0 {
		t.Fatalf("%v %v", err, past)
	}
	at := time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)
	want := []policy.Policy{
		{VM: "db", Mode: policy.Enforce, Allow: []string{"198.51.100.0/24"}, Source: "baseline", By: "alice", Applied: at, Revert: &policy.Revert{Until: at.Add(5 * time.Minute), Mode: policy.Audit, Allow: []string{"10.0.0.0/8"}, Source: "manual"}},
		{VM: "web", Mode: policy.Audit, Allow: []string{"203.0.113.0/24", "2001:db8::/32"}, Source: "manual", Applied: at},
	}
	if err := st.Save(want); err != nil {
		t.Fatal(err)
	}
	_, got, err := OpenPolicies(dir)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v\n got %+v\nwant %+v", err, got, want)
	}
}

func TestThePolicyFileIsPrivateAndWrittenWithoutATemporaryLeftBehind(t *testing.T) {
	dir := t.TempDir()
	st, _, _ := OpenPolicies(dir)
	if err := st.Save(nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "policies.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, info.Mode())
	}
	if _, err := os.Stat(filepath.Join(dir, "policies.json.tmp")); err == nil {
		t.Fatal("a temporary file was left behind")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "policies.json"))
	if string(b) != `{"version":1,"policies":[]}` {
		t.Fatalf("an empty list is [] and never null: %s", b)
	}
}

func TestAPolicyFileThatCannotBeReadIsSetAsideAndTheStoreStartsEmpty(t *testing.T) {
	for name, content := range map[string]string{"garbage": "{not json", "a version nobody wrote": `{"version":7,"policies":[{"vm":"web","mode":"enforce"}]}`, "empty": ""} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "policies.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		st, past, err := OpenPolicies(dir)
		if err != nil || st == nil || len(past) != 0 {
			t.Fatalf("%s: %v %v", name, err, past)
		}
		if _, err := os.Stat(filepath.Join(dir, "policies.json.corrupt")); err != nil {
			t.Fatalf("%s: the file was not kept for a person to look at: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "policies.json")); err == nil {
			t.Fatalf("%s: the bad file was left in place", name)
		}
		if err := st.Save([]policy.Policy{{VM: "web", Mode: policy.Audit}}); err != nil {
			t.Fatalf("%s: the store must work after that: %v", name, err)
		}
	}
}
