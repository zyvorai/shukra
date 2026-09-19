package detect

import (
	"net"
	"testing"
)

func TestMatch(t *testing.T) {
	w, err := ParseYAML([]byte(`
destinations:
  - cidr: 185.0.0.0/8
    severity: high
    name: unexpected-egress
  - cidr: 10.1.1.1
    name: exact
`))
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := w.Match(net.ParseIP("185.9.9.9"))
	if !ok || rule.Name != "unexpected-egress" || rule.Severity != "high" {
		t.Fatalf("%+v %v", rule, ok)
	}
	rule, ok = w.Match(net.ParseIP("10.1.1.1"))
	if !ok || rule.Severity != "high" {
		t.Fatalf("exact %+v", rule)
	}
	if _, ok := w.Match(net.ParseIP("8.8.8.8")); ok {
		t.Fatal("8.8.8.8 should not match")
	}
}

func TestRejectsBadCIDR(t *testing.T) {
	if _, err := ParseYAML([]byte("destinations:\n  - cidr: nope\n    name: x\n")); err == nil {
		t.Fatal("expected error")
	}
}
