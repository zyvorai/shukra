package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
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

// The daemon keeps a bounded event list. watch has to follow seq, not a count.
func TestWatchFollowsSeqAcrossPolls(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("since") {
		case "0":
			_, _ = w.Write([]byte(`{"seq":2049,"events":[{"seq":2048,"kind":"tcp_connect"},{"seq":2049,"kind":"tcp_connect"}]}`))
		case "2049":
			_, _ = w.Write([]byte(`{"seq":2050,"events":[{"seq":2050,"kind":"exec"}]}`))
		default:
			_, _ = w.Write([]byte(`{"seq":2050,"events":[]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)

	var buf bytes.Buffer
	since := uint64(0)
	for i := 0; i < 3; i++ {
		var err error
		if since, err = watchPoll(since, true, &buf); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Count(buf.String(), "\n"); got != 3 {
		t.Fatalf("printed %d events, want each exactly once: %q", got, buf.String())
	}
	if want := []string{"since=0", "since=2049", "since=2050"}; strings.Join(queries, ",") != strings.Join(want, ",") {
		t.Fatalf("queries %v, want %v", queries, want)
	}
}

func TestWatchResetsWhenDaemonRestarted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("since") == "0" {
			_, _ = w.Write([]byte(`{"seq":2,"events":[{"seq":1,"kind":"exec"},{"seq":2,"kind":"exec"}]}`))
			return
		}
		// The daemon is at seq 2 but the client asks from 5000.
		_, _ = w.Write([]byte(`{"seq":2,"events":[]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)

	var buf bytes.Buffer
	since, err := watchPoll(5000, true, &buf)
	if err != nil || since != 0 {
		t.Fatalf("since=%d err=%v", since, err)
	}
	if since, err = watchPoll(since, true, &buf); err != nil || since != 2 {
		t.Fatalf("since=%d err=%v", since, err)
	}
	if got := strings.Count(buf.String(), "\n"); got != 2 {
		t.Fatalf("printed %d: %q", got, buf.String())
	}
}

func TestRulesCheckAcceptsAndRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.yaml", "suppress: 2m\nports:\n  - {port: 25, name: smtp}\nthresholds:\n  - {name: slow, metric: block_iops, value: 5000}\n")
	var buf bytes.Buffer
	if err := run([]string{"rules", "check", good}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"would be accepted", "2m0s", "smtp", "slow"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}

	// The check must say no to what the daemon would refuse, including a typo.
	bad := write("bad.yaml", "threshold:\n  - name: x\n")
	buf.Reset()
	err := run([]string{"rules", "check", bad, "--json"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("typo accepted: %v", err)
	}
	if !strings.Contains(buf.String(), `"ok":false`) {
		t.Fatalf("json: %s", buf.String())
	}
	if err := run([]string{"rules", "check", dir + "/missing.yaml"}, &buf); err == nil {
		t.Fatal("a missing file was accepted")
	}
	if err := run([]string{"rules"}, &buf); err == nil {
		t.Fatal("usage error expected")
	}
}

func TestWatchStreamsAndResumesFromLastSeq(t *testing.T) {
	var mu sync.Mutex
	var resumedFrom []string
	connections := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/events":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"seq":3,"events":[]}`))
		case "/api/v1/stream":
			connections++
			resumedFrom = append(resumedFrom, r.Header.Get("Last-Event-ID"))
			w.Header().Set("Content-Type", "text/event-stream")
			if connections == 1 {
				fmt.Fprint(w, "id: 1\nevent: event\ndata: {\"seq\":1,\"kind\":\"exec\"}\n\n")
				fmt.Fprint(w, "id: 2\nevent: event\ndata: {\"seq\":2,\"kind\":\"vm_start\"}\n\n")
				fmt.Fprint(w, ": keepalive\n\n")
				return // the connection drops
			}
			fmt.Fprint(w, "id: 3\nevent: event\ndata: {\"seq\":3,\"kind\":\"tcp_connect\"}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sw := &safeWriter{w: &bytes.Buffer{}}
	done := make(chan error, 1)
	go func() { done <- watchLoop(ctx, sw, true, 20*time.Millisecond) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(sw.String(), "\n") >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	out := sw.String()
	for _, want := range []string{`"kind":"exec"`, `"kind":"vm_start"`, `"kind":"tcp_connect"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resumedFrom) < 2 || resumedFrom[0] != "0" || resumedFrom[1] != "2" {
		t.Fatalf("reconnect did not resume after the last seq it saw: %v", resumedFrom)
	}
}

func TestWatchFallsBackToPollingWithoutAStreamEndpoint(t *testing.T) {
	var polls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/api/v1/events" {
			http.NotFound(w, r) // an older daemon
			return
		}
		polls++
		w.Header().Set("Content-Type", "application/json")
		if polls == 1 {
			_, _ = w.Write([]byte(`{"seq":1,"events":[{"seq":1,"kind":"exec"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"seq":2,"events":[{"seq":2,"kind":"exit"}]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sw := &safeWriter{w: &bytes.Buffer{}}
	done := make(chan error, 1)
	go func() { done <- watchLoop(ctx, sw, true, 20*time.Millisecond) }()
	for i := 0; i < 150 && strings.Count(sw.String(), "\n") < 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if !strings.Contains(sw.String(), `"kind":"exec"`) || !strings.Contains(sw.String(), `"kind":"exit"`) {
		t.Fatalf("%s", sw.String())
	}
}

func TestWatchStopsOnABadKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"seq":0,"events":[]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := watchLoop(ctx, &bytes.Buffer{}, false, 10*time.Millisecond)
	if !errors.Is(err, errUnauthorized) {
		t.Fatalf("a rejected key should end watch with an error, got %v", err)
	}
}

// safeWriter lets the test read the buffer while the watcher writes to it.
type safeWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *safeWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.String()
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
