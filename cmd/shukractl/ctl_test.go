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

func TestMain(m *testing.M) {
	_ = os.Setenv("SHUKRA_SKIP_DOTENV", "1")
	_ = os.Setenv("SHUKRA_CLI_NO_BANNER", "1")
	os.Exit(m.Run())
}

func TestHelpHasTraceGroup(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if err := run(nil, &buf); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if strings.Contains(text, "\033") {
		t.Fatal("color leaked with NO_COLOR")
	}
	for _, want := range []string{"Trace", "trace kvm|sched|block|net", "shukractl", "eBPF-powered runtime intelligence and security for KVM", "SHUKRA_URL"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in help:\n%s", want, text)
		}
	}
}

func TestStatusJSONAndIsolateDoesNotAttach(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Shukra-Actor") != "shukractl" {
			t.Errorf("actor %q", r.Header.Get("X-Shukra-Actor"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/status":
			_, _ = w.Write([]byte(`{"version":"0.1.0","product":"shukra","mode":"observe","vms":1,"programsAttached":0,"programsTotal":4,"detections":0,"healthy":true,"summary":"observe"}`))
		case "/api/v1/trace/kvm":
			_, _ = w.Write([]byte(`{"rows":[{"vm":"payment-prod-03","exits":12}]}`))
		case "/api/v1/isolate":
			if r.Method != http.MethodPost {
				t.Fatalf("method %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"vm":"payment-prod-03","enforcement":"not_attached","applied":false,"reason":"TC/TCX tap enforcement is not in this build. No program was attached.","audit":{"result":"recorded_only"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	t.Setenv("SHUKRA_API_KEY", "secret")

	var buf bytes.Buffer
	if err := run([]string{"status", "--json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.Unmarshal(buf.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["product"] != "shukra" || status["mode"] != "observe" {
		t.Fatalf("%v", status)
	}

	buf.Reset()
	if err := run([]string{"trace", "kvm", "--json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var trace map[string]any
	if err := json.Unmarshal(buf.Bytes(), &trace); err != nil {
		t.Fatalf("%v %s", err, buf.String())
	}
	if trace["rows"] == nil {
		t.Fatalf("%v", trace)
	}

	buf.Reset()
	paths = nil
	if err := run([]string{"isolate", "payment-prod-03"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not attached") && !strings.Contains(buf.String(), "not_attached") {
		t.Fatalf("output %s", buf.String())
	}
	if strings.Contains(buf.String(), "applied       true") {
		t.Fatal("isolate claimed apply")
	}
	for _, p := range paths {
		if p != "POST /api/v1/isolate" {
			t.Fatalf("unexpected call %s in %v", p, paths)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	err := run([]string{"helm"}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), `unknown command "helm"`) {
		t.Fatal(err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
