package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
	"github.com/zyvorai/shukra/internal/state"
)

func TestEventShapeAndIsolate(t *testing.T) {
	st := state.New("node-07")
	st.AddEvent(event.Event{
		Kind: event.KindTCPConnect,
		TS:   time.Now().UTC(),
		VM:   event.VM{Name: "payment-prod-03", UUID: "u", Runtime: "qemu"},
		PID:  19321, TGID: 19321, Dst: "185.1.2.3", DPort: 443,
	})
	h := New(st, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?vm=payment-prod-03", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Events []event.Event `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 1 || body.Events[0].GuestAttributed || body.Events[0].Product != "shukra" || body.Events[0].Attribution != "qemu-process" {
		t.Fatalf("%+v", body.Events)
	}

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, unauth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("auth %d", rec.Code)
	}

	iso := httptest.NewRequest(http.MethodPost, "/api/v1/isolate", strings.NewReader(`{"vm":"payment-prod-03"}`))
	iso.Header.Set("Authorization", "Bearer secret")
	iso.Header.Set("X-Shukra-Actor", "shukractl")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, iso)
	var got state.Isolation
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Applied || got.Enforcement != "not_attached" || got.Audit.Result != "recorded_only" {
		t.Fatalf("%+v", got)
	}

	exp := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	exp.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, exp)
	if rec.Code != 200 {
		t.Fatalf("export %d %s", rec.Code, rec.Body.String())
	}
	var doc state.Export
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Status.Product != "shukra" || len(doc.Events) != 1 || doc.Events[0].GuestAttributed || len(doc.Net) != 1 || doc.Net[0].Connects != 1 {
		t.Fatalf("%+v", doc)
	}
}

func get(h http.Handler, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEmptyKeyFailsClosed(t *testing.T) {
	h := New(state.New("node-07"), "")
	if rec := get(h, "/api/v1/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty key, no header: %d", rec.Code)
	}
	if rec := get(h, "/api/v1/status", "anything"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty key, any header: %d", rec.Code)
	}
	if rec := get(NewNoAuth(state.New("node-07")), "/api/v1/status", ""); rec.Code != 200 {
		t.Fatalf("NewNoAuth: %d", rec.Code)
	}
}

func TestHealthIsOpenAndReadyWaitsForScan(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "secret")
	if rec := get(h, "/healthz", ""); rec.Code != 200 {
		t.Fatalf("healthz %d", rec.Code)
	}
	if rec := get(h, "/readyz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before scan %d", rec.Code)
	}
	st.SetPrograms(nil)
	if rec := get(h, "/readyz", ""); rec.Code != 200 {
		t.Fatalf("readyz after scan %d", rec.Code)
	}
	if rec := get(h, "/metrics", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without key %d", rec.Code)
	}
}

func TestEventsSince(t *testing.T) {
	st := state.New("node-07")
	for i := 0; i < 3; i++ {
		st.AddEvent(event.Event{Kind: event.KindTCPConnect, PID: 1})
	}
	h := New(st, "k")
	var body struct {
		Seq    uint64        `json:"seq"`
		Events []event.Event `json:"events"`
	}
	rec := get(h, "/api/v1/events?since=2", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Seq != 3 || len(body.Events) != 1 || body.Events[0].Seq != 3 {
		t.Fatalf("%+v", body)
	}
	if rec := get(h, "/api/v1/events?since=-1", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad since %d", rec.Code)
	}
}

func TestMetricsSkipUnmeasuredAndEscapeLabels(t *testing.T) {
	st := state.New("node-07")
	st.AddEvent(event.Event{Kind: event.KindTCPConnect, VM: event.VM{Name: "a\"b\nc"}, PID: 1})
	rec := get(New(st, "k"), "/metrics", "k")
	text := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		`shukra_program_attached{program="kvm"} 0`,
		`shukra_events_total 1`,
		`shukra_tcp_connects_total{vm="a\"b\nc"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	for _, bad := range []string{"shukra_kvm_exits_total{", "shukra_block_latency_seconds{"} {
		if strings.Contains(text, bad) {
			t.Fatalf("emitted a series for something not measured: %q", bad)
		}
	}
}

func TestStreamResumesAndFollows(t *testing.T) {
	st := state.New("node-07")
	st.AddEvent(event.Event{Kind: event.KindTCPConnect, PID: 1, Message: "old"})
	srv := httptest.NewServer(New(st, "k"))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer k")
	req.Header.Set("Last-Event-ID", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content-type %q", resp.Header.Get("Content-Type"))
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		st.AddEvent(event.Event{Kind: event.KindTCPConnect, PID: 1, Message: "new"})
	}()
	sc := bufio.NewScanner(resp.Body)
	var id, data string
	for sc.Scan() && data == "" {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "id: "); ok {
			id = v
		}
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			data = v
		}
	}
	if id != "2" || !strings.Contains(data, `"message":"new"`) {
		t.Fatalf("id=%q data=%q err=%v", id, data, sc.Err())
	}
}

func TestIsolationsEndpoint(t *testing.T) {
	st := state.New("node-07")
	st.Isolate("db", "shukractl")
	rec := get(New(st, "k"), "/api/v1/isolations", "k")
	var body struct {
		Isolations []state.Isolation `json:"isolations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Isolations) != 1 || body.Isolations[0].Applied {
		t.Fatalf("%+v", body)
	}
}

func TestMetricsShowSuppressionAndSinks(t *testing.T) {
	st := state.New("node-07")
	st.AddSuppressed(7)
	text := get(New(st, "k"), "/metrics", "k").Body.String()
	if !strings.Contains(text, "shukra_detections_suppressed_total 7") {
		t.Fatalf("%s", text)
	}
	if strings.Contains(text, "shukra_alert_sent_total") {
		t.Fatal("sink series without a sink configured")
	}
	st.SetSinkStats(func() []state.SinkStat { return []state.SinkStat{{Name: "webhook", Sent: 3, Failed: 2, Dropped: 1}} })
	text = get(New(st, "k"), "/metrics", "k").Body.String()
	for _, want := range []string{
		`shukra_alert_sent_total{sink="webhook"} 3`,
		`shukra_alert_failed_total{sink="webhook"} 2`,
		`shukra_alert_dropped_total{sink="webhook"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestSchedTraceThreadsAreOptIn(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	var body map[string]json.RawMessage
	if err := json.Unmarshal(get(h, "/api/v1/trace/sched", "k").Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["threads"]; ok {
		t.Fatal("threads returned without asking")
	}
	if err := json.Unmarshal(get(h, "/api/v1/trace/sched?threads=1", "k").Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["threads"]; !ok {
		t.Fatal("threads=1 did not return threads")
	}
}

// bucketsOf returns the le -> cumulative count pairs of one histogram series, in
// the order they were written, plus its _count.
func bucketsOf(t *testing.T, text, family, labels string) (les []string, cum []uint64, count uint64) {
	t.Helper()
	prefix := family + "_bucket{" + labels + ",le=\""
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			le, val, _ := strings.Cut(rest, "\"} ")
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				t.Fatalf("bad bucket line %q", line)
			}
			les, cum = append(les, le), append(cum, n)
		}
		if rest, ok := strings.CutPrefix(line, family+"_count{"+labels+"} "); ok {
			count, _ = strconv.ParseUint(rest, 10, 64)
		}
	}
	return
}

func hbuckets(pairs map[int]uint64) []uint64 {
	h := make([]uint64, 64)
	for i, n := range pairs {
		h[i] = n
	}
	return h
}

func TestMetricsExposeValidCumulativeHistograms(t *testing.T) {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}}})
	st.SetCounters(map[uint32]aggregate.Counters{
		100: {
			BlockIssues: 6, BlockReadOps: 4, BlockReadBytes: 16384, BlockWriteOps: 2, BlockWriteBytes: 8192,
			BlockReadMax: 3_000_000, BlockWriteMax: 900_000,
			// 3 fast (below the first le, so folded), 1 at ~1ms, and one 200s outlier.
			BlockRead:  hbuckets(map[int]uint64{2: 1, 4: 2, 19: 1, 37: 1}),
			BlockWrite: hbuckets(map[int]uint64{20: 2}),
			SchedHist:  hbuckets(map[int]uint64{10: 9, 14: 1}), OnCPUNs: 1,
			KVMLat: hbuckets(map[int]uint64{15: 5}), Entries: 5,
			Exits: map[uint32]uint64{12: 7, 48: 3}, ExitNs: map[uint32]uint64{12: 9_000_000_000, 48: 30_000},
		},
	})
	st.SetCPUVendor("GenuineIntel")
	text := get(New(st, "k"), "/metrics", "k").Body.String()

	les, cum, count := bucketsOf(t, text, "shukra_block_latency_seconds", `vm="db",op="read"`)
	if len(les) != 32 || les[len(les)-1] != "+Inf" { // le 2^7 .. 2^37 ns is 31 buckets, plus +Inf
		t.Fatalf("%d buckets, last %q: %v", len(les), les[len(les)-1], les)
	}
	for i := 1; i < len(cum); i++ {
		if cum[i] < cum[i-1] {
			t.Fatalf("cumulative counts went down at le=%s: %v", les[i], cum)
		}
	}
	if cum[0] != 3 || cum[len(cum)-1] != 5 || count != 5 {
		t.Fatalf("the three fast requests fold into the first bucket, and +Inf equals _count: first %d +Inf %d count %d", cum[0], cum[len(cum)-1], count)
	}
	// The 200 s request is beyond the last finite le, so only +Inf holds it.
	if cum[len(cum)-2] != 4 {
		t.Fatalf("outlier leaked into a finite bucket: %v", cum)
	}
	// Bucket 19 covers up to 2^20 ns = 1.048576 ms.
	found := false
	for i, le := range les {
		if le == "0.001048576" {
			found = true
			if cum[i] != 4 {
				t.Fatalf("le=%s has %d", le, cum[i])
			}
		}
	}
	if !found {
		t.Fatalf("no le for 2^20 ns: %v", les)
	}

	if strings.Contains(text, "shukra_block_latency_seconds_sum") || strings.Contains(text, "_runqueue_delay_seconds_sum") {
		t.Fatal("emitted a _sum the kernel histogram cannot support")
	}
	for _, fam := range []string{"shukra_block_latency_seconds", "shukra_sched_runqueue_delay_seconds", "shukra_kvm_exit_latency_seconds"} {
		if n := strings.Count(text, "# TYPE "+fam+" histogram"); n != 1 {
			t.Fatalf("%s: %d TYPE lines", fam, n)
		}
	}
	// A VM with no measured requests gets no series at all.
	for _, want := range []string{
		`shukra_block_ops_total{vm="db",op="read"} 4`,
		`shukra_block_ops_total{vm="db",op="write"} 2`,
		`shukra_block_bytes_total{vm="db",op="write"} 8192`,
		`shukra_block_latency_max_seconds{vm="db",op="read"} 0.003`,
		`shukra_kvm_exit_latency_seconds_count{vm="db"} 5`,
		`shukra_sched_runqueue_delay_seconds_count{vm="db"} 10`,
		`shukra_kvm_exits_by_reason_total{vm="db",reason="12",name="hlt"} 7`,
		`shukra_kvm_exits_by_reason_total{vm="db",reason="48",name="ept_violation"} 3`,
		`shukra_kvm_exit_handling_seconds_total{vm="db",reason="12",name="hlt"} 9`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestMetricsDoNotNameKVMReasonsOnOtherVendors(t *testing.T) {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	st.SetCounters(map[uint32]aggregate.Counters{100: {Entries: 1, Exits: map[uint32]uint64{12: 7}}})
	for _, vendor := range []string{"AuthenticAMD", ""} {
		st.SetCPUVendor(vendor)
		text := get(New(st, "k"), "/metrics", "k").Body.String()
		if !strings.Contains(text, `shukra_kvm_exits_by_reason_total{vm="db",reason="12"} 7`) || strings.Contains(text, `name="hlt"`) {
			t.Fatalf("vendor %q:\n%s", vendor, text)
		}
	}
}

func TestReadOnlyKeyCanReadButNotAct(t *testing.T) {
	st := state.New("node-07")
	h := NewWithKeys(st, Keys{Admin: "admin-key", ReadOnly: "scrape-key"})
	do := func(method, path, key string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"vm":"db"}`))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		method, path, key string
		want              int
	}{
		{"GET", "/api/v1/status", "scrape-key", 200},
		{"GET", "/metrics", "scrape-key", 200},
		{"GET", "/api/v1/stream?since=0", "", 401},
		{"POST", "/api/v1/isolate", "scrape-key", 403},
		{"POST", "/api/v1/isolate", "admin-key", 200},
		{"POST", "/api/v1/isolate", "wrong", 401},
		{"GET", "/api/v1/status", "admin-key", 200},
	} {
		if c.path == "/api/v1/stream?since=0" {
			continue // a long-lived response; the 401 path is covered by the other cases
		}
		if got := do(c.method, c.path, c.key); got != c.want {
			t.Errorf("%s %s with %q: %d, want %d", c.method, c.path, c.key, got, c.want)
		}
	}
	if len(st.Isolations()) != 1 {
		t.Fatalf("only the admin key's request should have been recorded: %d", len(st.Isolations()))
	}
}

func TestAnEmptyReadOnlyKeyNeverMatches(t *testing.T) {
	h := NewWithKeys(state.New("n"), Keys{Admin: "admin-key"}) // no read-only key configured
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an empty bearer matched an unset key: %d", rec.Code)
	}
	if rec = get(NewWithKeys(state.New("n"), Keys{ReadOnly: "r"}), "/api/v1/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key at all: %d", rec.Code)
	}
}

func TestExplainWindowParameter(t *testing.T) {
	h := New(state.New("node-07"), "k")
	for _, c := range []struct {
		q    string
		want int
		win  string
	}{
		{"", 200, "lifetime"}, // no history yet, so the default window falls back
		{"&window=lifetime", 200, "lifetime"}, {"&window=0", 200, "lifetime"},
		{"&window=5m", 200, "lifetime"}, {"&window=90s", 200, "lifetime"},
		{"&window=9s", 400, ""}, {"&window=6m", 400, ""}, {"&window=banana", 400, ""}, {"&window=-1m", 400, ""},
	} {
		rec := get(h, "/api/v1/explain?vm=x"+c.q, "k")
		if rec.Code != c.want {
			t.Errorf("%q: %d, want %d", c.q, rec.Code, c.want)
			continue
		}
		if c.want == 200 {
			var body struct {
				Window string `json:"window"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Window != c.win {
				t.Errorf("%q: window %q (%v), want %q", c.q, body.Window, err, c.win)
			}
		}
	}
}

func TestDoctorEndpointReportsTheWorstFindingAndIsReadableWithTheReadOnlyKey(t *testing.T) {
	// Distinctive values, so that finding one in the output could only mean a leak.
	const admin, readOnly = "adm-7f3a91c2e5", "ro-4b8d60aa19"
	st := state.New("node-07")
	st.SetConfig(state.ConfigInfo{Listen: "0.0.0.0:30970", DevKey: true, KeyLen: len(admin), ReadOnlyKey: true})
	h := NewWithKeys(st, Keys{Admin: admin, ReadOnly: readOnly})
	rec := get(h, "/api/v1/doctor", readOnly)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Worst  string        `json:"worst"`
		Checks []state.Check `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Worst != "fail" || len(body.Checks) == 0 || body.Checks[0].Status != "fail" {
		t.Fatalf("%+v", body)
	}
	for _, k := range []string{admin, readOnly} {
		if strings.Contains(rec.Body.String(), k) {
			t.Fatalf("the audit output contains a key: %s", k)
		}
	}
	if get(h, "/api/v1/doctor", "").Code != http.StatusUnauthorized {
		t.Fatal("doctor is open without a key")
	}
}

func TestEmptyListsAreArraysNotNull(t *testing.T) {
	srv := New(state.New("node-07"), "k")
	for path, key := range map[string]string{
		"/api/v1/vms": "vms", "/api/v1/trace/kvm": "rows", "/api/v1/trace/sched": "rows",
		"/api/v1/trace/block": "rows", "/api/v1/trace/net": "rows", "/api/v1/trace/tap": "rows",
	} {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(get(srv, path, "k").Body.Bytes(), &body); err != nil {
			t.Fatal(path, err)
		}
		if got := string(body[key]); got != "[]" {
			t.Errorf("%s: %q is %s, not []: a client cannot take its length", path, key, got)
		}
	}
}
