package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestExplainPassesTheWindowAndShowsWhichOneWasUsed(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"question":"why is this VM slow?","window":"1m0s","findings":[],"evidence":[],"missing":[]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"explain", "db", "--window", "5m"}, &buf); err != nil {
		t.Fatal(err)
	}
	if query != "vm=db&window=5m" || !strings.Contains(buf.String(), "(window: 1m0s)") {
		t.Fatalf("query %q output %q", query, buf.String())
	}
	if err := run([]string{"explain", "db"}, &bytes.Buffer{}); err != nil || query != "vm=db" {
		t.Fatalf("no --window must not send one: %q %v", query, err)
	}
}

func TestExplainPrintsRankedFindingsBeforeEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"question":"why is this VM slow?","basis":"Latencies are lifetime.","evidence":["e1"],"missing":["m1"],
			"findings":[{"cause":"storage_latency","confidence":"high","summary":"Block requests take long.","evidence":["Block write p99 is up to 60 ms."]},
			{"cause":"no_host_cause","confidence":"low","summary":"Nothing crossed."}]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"explain", "db"}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	i, j := strings.Index(out, "[high] storage_latency"), strings.Index(out, "\nevidence\n")
	if i < 0 || j < 0 || i > j || !strings.Contains(out, "Block write p99 is up to 60 ms.") || !strings.Contains(out, "[low] no_host_cause") || !strings.Contains(out, "note: Latencies are lifetime.") {
		t.Fatalf("%s", out)
	}
}

func TestCLITrustsAPrivateCAOnlyWhenTold(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	// httpClient is what do() builds its transport from. loadConfig turns
	// verification off by design for a loopback https URL, so test it directly.
	t.Setenv("SHUKRA_TLS_INSECURE", "")
	t.Setenv("SHUKRA_CA_FILE", "")
	if resp, err := httpClient().Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("an unknown certificate was trusted with no CA configured")
	}
	ca := t.TempDir() + "/ca.pem"
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHUKRA_CA_FILE", ca)
	resp, err := httpClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("the configured CA was not trusted: %v", err)
	}
	resp.Body.Close()
	// Pointing at a file with no certificate must not quietly disable checking.
	bad := t.TempDir() + "/bad.pem"
	if err := os.WriteFile(bad, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHUKRA_CA_FILE", bad)
	if resp, err := httpClient().Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("a broken CA file fell back to trusting everything")
	}
}

func TestVersionCommand(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"version"}, &buf); err != nil || !strings.HasPrefix(buf.String(), "shukractl ") {
		t.Fatalf("%q %v", buf.String(), err)
	}
	buf.Reset()
	if err := run([]string{"--version"}, &buf); err != nil || !strings.HasPrefix(buf.String(), "shukractl ") {
		t.Fatalf("%q %v", buf.String(), err)
	}
}

func TestIsolateAndReleasePrintWhatActuallyHappened(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/isolate":
			_, _ = w.Write([]byte(`{"vm":"db","enforcement":"tcx","applied":true,"taps":["tap0","tap1"],"reason":"Traffic is dropped, except ARP and 10.0.0.1/32.","audit":{"result":"applied"}}`))
		case "/api/v1/release":
			_, _ = w.Write([]byte(`{"vm":"db","enforcement":"tcx","applied":true,"taps":["tap0"],"reason":"Isolation lifted on tap0.","audit":{"result":"applied"}}`))
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"isolate", "db"}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ISOLATE  db", "enforcement   tcx", "applied       true", "taps          tap0, tap1", "10.0.0.1/32"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "enforcement is not attached") {
		t.Fatalf("an applied isolation was described as not attached:\n%s", out)
	}
	buf.Reset()
	if err := run([]string{"release", "db"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "RELEASE  db") || !strings.Contains(buf.String(), "Isolation lifted") {
		t.Fatalf("%s", buf.String())
	}
	if len(paths) != 2 || paths[0] != "POST /api/v1/isolate" || paths[1] != "POST /api/v1/release" {
		t.Fatalf("%v", paths)
	}
	if err := run([]string{"release"}, &buf); err == nil {
		t.Fatal("release with no VM should be a usage error")
	}
}

func TestRefusedIsolateIsNeverShownAsDone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vm":"db","enforcement":"not_attached","applied":false,"reason":"no management allow list is configured (-isolate-allow), so refusing to isolate","audit":{"result":"refused"}}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"isolate", "db"}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "applied       false") || !strings.Contains(out, "allow list") || !strings.Contains(out, "no datapath change") {
		t.Fatalf("%s", out)
	}
}

func TestTraceTapAndSecurityShowTheGuestTrafficAndTheAllowList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/trace/tap":
			_, _ = w.Write([]byte(`{"note":"Traffic seen on the host side of each VM tap.","rows":[{"vm":"db","tap":"tap0","fromGuestBytes":1200,"fromGuestPackets":10,"toGuestBytes":3400,"toGuestPackets":12,"droppedPackets":5,"isolated":true}]}`))
		case "/api/v1/security":
			_, _ = w.Write([]byte(`{"vm":"db","enforcement":"tcx","allowList":["10.0.0.1/32"],"detections":[{"severity":"high","dst":"1.2.3.4","message":"x","guest_attributed":true,"attribution":"guest-tap"}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"trace", "tap"}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tap=tap0", "from_guest=1200 B/10 pkts", "dropped=5 pkts", "isolated=true"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := run([]string{"security", "db"}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"enforcement=tcx", "management allow list: 10.0.0.1/32", "guest_attributed=true", "attribution=guest-tap"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
}

func doctorServer(t *testing.T, worst string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"worst":"` + worst + `","checks":[
			{"id":"auth","status":"fail","title":"The API key is the well-known dev key","detail":"It is public knowledge.","fix":"Set a real key."},
			{"id":"transport","status":"warn","title":"The API is plain HTTP on a non-loopback address","fix":"Add -tls-cert."},
			{"id":"alerts","status":"info","title":"No alert sink is configured"},
			{"id":"persistence","status":"ok","title":"State is kept in /var/lib/shukra"}]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SHUKRA_URL", srv.URL)
}

func TestDoctorPrintsWhatNeedsAttentionAndHowToFixIt(t *testing.T) {
	doctorServer(t, "fail")
	var buf bytes.Buffer
	err := run([]string{"doctor"}, &buf)
	if err == nil {
		t.Fatal("a failing audit must exit non-zero, so a deploy can gate on it")
	}
	out := buf.String()
	for _, want := range []string{"[FAIL] The API key is the well-known dev key", "fix: Set a real key.", "[warn] The API is plain HTTP", "[info] No alert sink", "1 checks passed, 3 need attention (worst: fail)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "State is kept") {
		t.Fatalf("a passing check was printed:\n%s", out)
	}
}

func TestDoctorExitStatusFollowsTheWorstFinding(t *testing.T) {
	for _, c := range []struct {
		worst  string
		args   []string
		wantOK bool
	}{
		{"ok", nil, true}, {"info", nil, true}, {"warn", nil, true}, {"warn", []string{"--strict"}, false},
		{"fail", nil, false}, {"fail", []string{"--strict"}, false}, {"info", []string{"--strict"}, true},
	} {
		doctorServer(t, c.worst)
		err := run(append([]string{"doctor"}, c.args...), &bytes.Buffer{})
		if (err == nil) != c.wantOK {
			t.Errorf("worst=%s args=%v: err=%v, want ok=%v", c.worst, c.args, err, c.wantOK)
		}
	}
}

func TestDoctorJSONIsThePlainReport(t *testing.T) {
	doctorServer(t, "warn")
	var buf bytes.Buffer
	if err := run([]string{"doctor", "--json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil || m["worst"] != "warn" {
		t.Fatalf("%v %s", err, buf.String())
	}
}

func TestTraceDropsSaysWhoseDropsTheyAreAndWhereTheyHappened(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/trace/drops" {
			_, _ = w.Write([]byte(`{"measured":true,"note":"Packets the kernel dropped.","taps":[{"vm":"db","tap":"tap0","kernelDrops":60,"shukraDropped":2,"otherDrops":58,"guestNotReading":0}],"rows":[{"vm":"db","tap":"tap0","reason":"TC_INGRESS","count":60,"location":"__netif_receive_skb_core"}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"trace", "drops"}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vm=db", "tap=tap0", "kernel=60", "shukra=2", "other=58", "TC_INGRESS", "60", "freed in __netif_receive_skb_core"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
}

func TestTraceDropsSaysWhenTheProgramIsNotMeasuring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"measured":false,"rows":[],"taps":[]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"trace", "drops"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not measuring") || strings.Contains(buf.String(), "kernel=") {
		t.Fatalf("%s", buf.String())
	}
}

func TestTraceSchedShowsWhoTookTheVCPUsCPU(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rows":[
			{"vm":"db","onCpuNs":9000,"wakeupDelayNs":10,"wakeupCount":2,"vcpuPreemptedNs":3500000000,"vcpuPreemptions":42,"topPreemptors":[{"who":"vm:web","ns":3000000000},{"who":"kworker","ns":500000000}]},
			{"vm":"quiet","onCpuNs":1,"vcpuPreemptedNs":0,"vcpuPreemptions":0,"topPreemptors":[]}]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"trace", "sched"}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vCPU preempted: 3500000000ns over 42 preemptions  (taken by: vm:web 3000000000ns, kworker 500000000ns)", "vCPU preempted: 0ns over 0 preemptions\n"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
}

func TestExplainAtSendsAnEscapedTimeAndShowsWhenAndHowCoarse(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"question":"why was this VM slow?","window":"5m0s","at":"2026-09-20T03:12:00Z","resolution":"5m0s snapshots: the verdict stands on A and B","findings":[],"evidence":[],"missing":[]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"explain", "db", "--at", "2026-09-20T09:12:00+05:30", "--window", "15m"}, &buf); err != nil {
		t.Fatal(err)
	}
	if query != "at=2026-09-20T09%3A12%3A00%2B05%3A30&vm=db&window=15m" {
		t.Fatalf("a + in a time must not become a space: %q", query)
	}
	for _, want := range []string{"(at: 2026-09-20T03:12:00Z)", "resolution: 5m0s snapshots"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
}

func incidentServer(t *testing.T) *string {
	t.Helper()
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"product":"shukra","vm":"db","at":"2026-09-20T03:12:00Z","window":"15m0s",
			"explain":{"question":"why was this VM slow?","window":"15m0s","findings":[{"cause":"cpu_preempted","confidence":"high","summary":"s","evidence":["e1"]}],"evidence":[],"missing":[]},
			"detections":[{"ts":"2026-09-20T03:10:00Z","severity":"high","message":"new destination"}],"events":[{},{}],"isolations":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SHUKRA_URL", srv.URL)
	return &query
}

func TestIncidentPrintsASummaryAndPointsToTheWholeBundle(t *testing.T) {
	query := incidentServer(t)
	var buf bytes.Buffer
	if err := run([]string{"incident", "db", "--at", "-90m", "--window", "15m"}, &buf); err != nil {
		t.Fatal(err)
	}
	if *query != "at=-90m&vm=db&window=15m" {
		t.Fatalf("%q", *query)
	}
	for _, want := range []string{"INCIDENT  vm=db", "cpu_preempted", "detections (1)", "new destination", "recorder events: 2", "--out FILE"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
	if err := run([]string{"incident"}, &bytes.Buffer{}); err == nil {
		t.Fatal("a VM is required")
	}
	if err := run([]string{"incident", "--at", "-1h"}, &bytes.Buffer{}); err == nil {
		t.Fatal("a VM is required before the flags")
	}
}

func TestIncidentOutWritesAPrivateFileAndDoesNotPrintTheBundle(t *testing.T) {
	incidentServer(t)
	file := filepath.Join(t.TempDir(), "inc.json")
	var buf bytes.Buffer
	if err := run([]string{"incident", "db", "--out", file}, &buf); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the bundle names VMs and addresses and must be private: %v %v", fi, err)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), `"product":"shukra"`) || strings.Contains(buf.String(), "new destination") {
		t.Fatalf("file %q output %q", b, buf.String())
	}
	if !strings.Contains(buf.String(), "wrote "+file) || !strings.Contains(buf.String(), "treat it like the event list") {
		t.Fatalf("%q", buf.String())
	}
	var raw bytes.Buffer
	if err := run([]string{"incident", "db", "--json"}, &raw); err != nil || !strings.HasPrefix(raw.String(), "{") {
		t.Fatalf("--json prints the document: %v %q", err, raw.String())
	}
}

func TestTraceContentionShowsWhoTookWhoseCPUAndWhatTheCulpritDid(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"note":"n","window":"1m0s",
			"pairs":[{"victim":"db","culprit":"web","preemptedNs":800000000,"share":0.8}],
			"victims":[{"vm":"db","preemptedNs":1000000000,"preemptions":30,"byOtherVmsNs":800000000,"bySelfNs":100000000,"byHostNs":100000000,"topHostTasks":[{"who":"kworker","ns":60000000}]},
			           {"vm":"quiet","preemptedNs":0,"preemptions":0,"byOtherVmsNs":0,"bySelfNs":0,"byHostNs":0,"topHostTasks":[]}],
			"culprits":[{"vm":"web","tookNs":800000000,"victims":1,"onCpuNs":9000000000,"exits":700}]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"trace", "contention", "--vm", "db", "--window", "5m"}, &buf); err != nil {
		t.Fatal(err)
	}
	if query != "vm=db&window=5m" {
		t.Fatalf("%q", query)
	}
	for _, want := range []string{
		"TRACE CONTENTION  window=1m0s",
		"vm=db  preempted=1000000000ns over 30 preemptions  (other VMs 800000000ns, its own threads 100000000ns, host tasks 100000000ns)",
		"taken by VM web: 800000000ns (80%)", "taken by host tasks: kworker 60000000ns",
		"vm=web  took=800000000ns from 1 VMs  its own on-cpu=9000000000ns  exits=700", "vm=quiet  preempted=0ns",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
	if err := run([]string{"trace", "sched", "--window", "5m"}, &bytes.Buffer{}); err != nil || query != "" {
		t.Fatalf("--window is only for contention: %q %v", query, err)
	}
}

func TestBaselineOffSaysHowToTurnItOn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":false,"persisted":false,"rows":[],"items":[]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"baseline"}, &buf); err != nil || !strings.Contains(buf.String(), "off: the rules file has no baselines section") {
		t.Fatalf("%v %q", err, buf.String())
	}
}

func TestBaselineShowsWhereEachVMsLearningStandsAndWhatItLearned(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"persisted":false,"learn":"24h0m0s","maxAlertsPerDay":20,
			"rows":[{"vm":"web","learning":true,"learnUntil":"2026-09-21T03:00:00Z","alertsToday":0,"suppressed":0,"counts":[{"kind":"destination","count":4},{"kind":"dns-suffix","count":2},{"kind":"inbound-peer","count":0}]},
			        {"vm":"db","learning":false,"learnUntil":"2026-09-20T03:00:00Z","alertsToday":3,"suppressed":5,"counts":[{"kind":"destination","count":9},{"kind":"dns-suffix","count":1},{"kind":"inbound-peer","count":1}]}],
			"items":[{"kind":"destination","item":"203.0.113.0/24","first":"2026-09-20T03:00:00Z","last":"2026-09-20T04:00:00Z"}]}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	var buf bytes.Buffer
	if err := run([]string{"baseline", "web", "--items"}, &buf); err != nil {
		t.Fatal(err)
	}
	if query != "items=1&vm=web" {
		t.Fatalf("%q", query)
	}
	for _, want := range []string{
		"learning period 24h0m0s, at most 20 new-item alerts per VM per day", "WARNING: not kept across a restart",
		"vm=web  learning until 2026-09-21T03:00:00Z  (destination 4, dns-suffix 2, inbound-peer 0)",
		"vm=db  reporting  (destination 9, dns-suffix 1, inbound-peer 1)  new alerts today 3, held back in all 5",
		"learned, most recently seen first", "203.0.113.0/24",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q:\n%s", want, buf.String())
		}
	}
	if err := run([]string{"baseline"}, &buf); err != nil || query != "" {
		t.Fatalf("no VM, no items request: %q %v", query, err)
	}
}

func TestBaselineForgetPostsTheVMAndNeedsOne(t *testing.T) {
	var method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vm":"web","forgotten":true}`))
	}))
	defer srv.Close()
	t.Setenv("SHUKRA_URL", srv.URL)
	if err := run([]string{"baseline", "--forget"}, &bytes.Buffer{}); err == nil {
		t.Fatal("forgetting needs a VM: it must not forget everything by default")
	}
	var buf bytes.Buffer
	if err := run([]string{"baseline", "web", "--forget"}, &buf); err != nil {
		t.Fatal(err)
	}
	if method != "POST" || path != "/api/v1/baseline/forget" || body != `{"vm":"web"}` || !strings.Contains(buf.String(), "recorded as a detection") {
		t.Fatalf("%s %s %s %q", method, path, body, buf.String())
	}
}
