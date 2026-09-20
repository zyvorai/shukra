package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A VM name is text the operator typed, and it goes into a query string: a name with an &, a # or a space
// must arrive as that name, not cut off or split into other parameters.
func TestRecorderAndSecurityEscapeTheVMNameAndTheWindow(t *testing.T) {
	const name = "web & db #1"
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		got = append(got, map[string]string{"path": r.URL.Path, "vm": q.Get("vm"), "window": q.Get("window"), "raw": r.URL.RawQuery})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vm":"","window":"","events":[],"detections":[],"allowList":[],"enforcement":"off"}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"recorder", name, "--window", "90s"}, &buf); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"security", name}, &buf); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d requests", len(got))
	}
	for _, g := range got {
		if g["vm"] != name {
			t.Fatalf("%s asked for VM %q, want %q (query %q)", g["path"], g["vm"], name, g["raw"])
		}
	}
	if got[0]["window"] != "90s" {
		t.Fatalf("the window was lost: %q", got[0]["raw"])
	}
}

// The API leaves the time of an action that never had a release timer at Go's zero time. That is not a
// promise to release at year 1.
func TestAnActionWithNoReleaseTimerDoesNotPromiseOne(t *testing.T) {
	actionsServer(t, `{"enabled":true,"pending":0,"actions":[
		{"id":"a-1","status":"executed","vm":"db","response":"auto","mode":"enforce","rule":"c2","severity":"high","message":"m","result":"isolated","releaseAt":"0001-01-01T00:00:00Z"},
		{"id":"a-2","status":"executed","vm":"db","response":"auto","mode":"enforce","rule":"c2","severity":"high","message":"m","result":"isolated","releaseAt":"2026-09-20T03:10:00Z"}]}`)
	var buf bytes.Buffer
	if err := run([]string{"actions", "--all"}, &buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "0001-01-01") {
		t.Fatalf("year 1 is not a release time:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "releases itself at 2026-09-20T03:10:00Z") {
		t.Fatalf("a real release timer must still be shown:\n%s", buf.String())
	}
}

// An event with no destination (every VMM tripwire event is one) prints no destination, not <nil>.
func TestWatchPrintsNoDestinationForAnEventThatHasNone(t *testing.T) {
	var buf bytes.Buffer
	for _, e := range []map[string]any{
		{"ts": "T1", "kind": "vmm_syscall", "attribution": "qemu-process", "vm": map[string]any{"name": "web"}, "syscall": "ptrace", "comm": "qemu", "pid": 7},
		{"ts": "T2", "kind": "tcp_connect", "attribution": "qemu-process", "vm": map[string]any{"name": "web"}, "dst": "203.0.113.9"},
	} {
		if err := printEvent(e, false, &buf); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if strings.Contains(lines[0], "<nil>") || strings.Contains(lines[0], "dst=") {
		t.Fatalf("no destination, none printed: %q", lines[0])
	}
	if !strings.Contains(lines[0], "syscall=ptrace") {
		t.Fatalf("the call must still be shown: %q", lines[0])
	}
	if !strings.Contains(lines[1], "dst=203.0.113.9") {
		t.Fatalf("a destination must still be shown: %q", lines[1])
	}
}

// rules check --json is read by a script: a list with nothing in it is [], not null.
func TestRulesCheckJSONListsAreListsWhenEmpty(t *testing.T) {
	p := t.TempDir() + "/empty.yaml"
	if err := os.WriteFile(p, []byte("suppress: 2m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := run([]string{"rules", "check", p, "--json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ports", "execAllow", "thresholds", "responses"} {
		if l, ok := doc[k].([]any); !ok || len(l) != 0 {
			t.Fatalf("%s must be an empty list, got %#v in %s", k, doc[k], buf.String())
		}
	}
}
