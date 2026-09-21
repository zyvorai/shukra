package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/baseline"
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
		"/api/v1/trace/block": "rows", "/api/v1/trace/net": "rows", "/api/v1/trace/tap": "rows", "/api/v1/trace/drops": "rows",
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

func withDrops(attached bool) *state.State {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	status := "detached"
	if attached {
		status = "attached"
	}
	st.SetPrograms([]state.Program{{Name: "tap", Status: "attached"}, {Name: "drops", Status: status}})
	var isolated uint64
	st.SetTapSource(func() []state.TapStat { return []state.TapStat{{Name: "tap0", DroppedPkts: isolated}} })
	st.SetDropSource(func() []state.DropStat {
		return []state.DropStat{{Tap: "tap0", Reason: "TC_INGRESS", Count: 40, Location: "__netif_receive_skb_core"}, {Tap: "tap9", Reason: "TC_INGRESS", Count: 7}}
	})
	st.Drops("") // the daemon's first look, before Shukra has dropped anything
	isolated = 3
	return st
}

func TestDropsEndpointServesTheRowsAndTheSummaryForOwnedTapsOnly(t *testing.T) {
	var body struct {
		Measured bool `json:"measured"`
		Rows     []struct {
			VM, Tap, Reason, Location string
			Count                     uint64
		} `json:"rows"`
		Taps []struct {
			VM            string `json:"vm"`
			ShukraDropped uint64 `json:"shukraDropped"`
			OtherDrops    uint64 `json:"otherDrops"`
		} `json:"taps"`
	}
	rec := get(New(withDrops(true), "k"), "/api/v1/trace/drops", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Measured || len(body.Rows) != 1 || body.Rows[0].VM != "db" || body.Rows[0].Reason != "TC_INGRESS" || body.Rows[0].Count != 40 || body.Rows[0].Location != "__netif_receive_skb_core" {
		t.Fatalf("tap9 belongs to no VM and must not be shown: %s", rec.Body.String())
	}
	if len(body.Taps) != 1 || body.Taps[0].ShukraDropped != 3 || body.Taps[0].OtherDrops != 37 {
		t.Fatalf("%s", rec.Body.String())
	}
}

func TestATapWithNoDropsHasAnEmptyReasonListNotNull(t *testing.T) {
	st := withDrops(true)
	st.SetDropSource(func() []state.DropStat { return nil }) // measuring, and nothing has been dropped
	rec := get(New(st, "k"), "/api/v1/trace/drops", "k")
	var body struct {
		Taps []map[string]json.RawMessage `json:"taps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Taps) != 1 || string(body.Taps[0]["reasons"]) != "[]" {
		t.Fatalf("reasons must be [] so a client can loop over it: %s", rec.Body.String())
	}
}

func TestDropsEndpointSaysNotMeasuringAndInventsNothing(t *testing.T) {
	rec := get(New(withDrops(false), "k"), "/api/v1/trace/drops", "k")
	var body struct {
		Measured bool              `json:"measured"`
		Rows     []json.RawMessage `json:"rows"`
		Taps     []json.RawMessage `json:"taps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Measured || body.Rows == nil || len(body.Rows) != 0 || body.Taps == nil || len(body.Taps) != 0 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
}

func TestDropMetricsExistOnlyWhileTheProgramMeasures(t *testing.T) {
	on := get(New(withDrops(true), "k"), "/metrics", "k").Body.String()
	if !strings.Contains(on, `shukra_tap_kernel_drops_total{vm="db",tap="tap0",reason="TC_INGRESS"} 40`) || strings.Contains(on, "tap9") {
		t.Fatalf("%s", on)
	}
	off := get(New(withDrops(false), "k"), "/metrics", "k").Body.String()
	if strings.Contains(off, "shukra_tap_kernel_drops_total") {
		t.Fatalf("a series with no measurement behind it:\n%s", off)
	}
}

func withOutcomes() *state.State {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	st.SetPrograms([]state.Program{{Name: "tap", Status: "attached"}})
	hist := make([]uint64, 64)
	hist[17], hist[18] = 30, 10 // bucket 17 is 131 to 262 us, bucket 18 is 262 to 524 us
	st.SetTapSource(func() []state.TapStat {
		return []state.TapStat{{Name: "tap0", HandshakeHist: hist, Outcomes: state.Outcomes{
			OutSyn: 50, OutOK: 40, OutRefused: 6, OutTimeout: 3, OutBlocked: 1, OutRetrans: 4,
			InSyn: 9, InOK: 2, InRefused: 3, InIgnored: 4, InRetrans: 1,
		}}}
	})
	return st
}

func TestTapRowsCarryTheHandshakeOutcomesAndTheirLatency(t *testing.T) {
	rec := get(New(withOutcomes(), "k"), "/api/v1/trace/tap", "k")
	var body struct {
		Rows []map[string]json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Rows) != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	r := body.Rows[0]
	for k, want := range map[string]string{
		"outSyn": "50", "outAccepted": "40", "outRefused": "6", "outTimedOut": "3", "outBlocked": "1", "outRetransmits": "4",
		"inSyn": "9", "inAccepted": "2", "inRefused": "3", "inIgnored": "4", "inRetransmits": "1",
	} {
		if string(r[k]) != want {
			t.Errorf("%s = %s, want %s", k, r[k], want)
		}
	}
	// Percentiles are a bucket's high edge: 30 of the 40 are in bucket 17, whose edge is 2^18 ns, and the
	// slowest 10 are in bucket 18, whose edge is 2^19 ns.
	if string(r["handshakeP50Ns"]) != "262144" || string(r["handshakeP99Ns"]) != "524288" {
		t.Errorf("p50 = %s p99 = %s", r["handshakeP50Ns"], r["handshakeP99Ns"])
	}
	// A tap with no handshakes has [] and not null for the histogram.
	empty := state.New("n")
	empty.SetVMs([]identity.VM{{Name: "db", Taps: []string{"tap0"}}})
	empty.SetTapSource(func() []state.TapStat { return []state.TapStat{{Name: "tap0"}} })
	var eb struct {
		Rows []map[string]json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(get(New(empty, "k"), "/api/v1/trace/tap", "k").Body.Bytes(), &eb); err != nil || string(eb.Rows[0]["handshakeHist"]) != "[]" {
		t.Fatalf("%v %s", err, eb.Rows[0]["handshakeHist"])
	}
}

func TestOutcomeMetricsSplitByDirectionAndResultAndHaveALatencyHistogram(t *testing.T) {
	text := get(New(withOutcomes(), "k"), "/metrics", "k").Body.String()
	for _, want := range []string{
		`shukra_tap_connect_attempts_total{vm="db",tap="tap0",direction="out"} 50`,
		`shukra_tap_connect_attempts_total{vm="db",tap="tap0",direction="in"} 9`,
		`shukra_tap_connect_outcomes_total{vm="db",tap="tap0",direction="out",result="accepted"} 40`,
		`shukra_tap_connect_outcomes_total{vm="db",tap="tap0",direction="out",result="refused"} 6`,
		`shukra_tap_connect_outcomes_total{vm="db",tap="tap0",direction="out",result="timed_out"} 3`,
		`shukra_tap_connect_outcomes_total{vm="db",tap="tap0",direction="out",result="blocked"} 1`,
		`shukra_tap_connect_outcomes_total{vm="db",tap="tap0",direction="in",result="ignored"} 4`,
		`shukra_tap_connect_retransmits_total{vm="db",tap="tap0",direction="out"} 4`,
		`shukra_tap_handshake_seconds_count{vm="db",tap="tap0"} 40`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestMetricsExposeVCPUPreemptionByWhoTookTheCPU(t *testing.T) {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}}, {Name: "idle", PID: 200, Threads: []int{200}}})
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 5, PreemptNs: 3_500_000_000, Preemptors: map[string]uint64{"vm:web": 3_000_000_000, "kworker": 500_000_000, `we"ird`: 0}},
	})
	text := get(New(st, "k"), "/metrics", "k").Body.String()
	for _, want := range []string{
		`shukra_sched_vcpu_preempted_seconds_total{vm="db"} 3.5`,
		`shukra_sched_vcpu_preempted_by_seconds_total{vm="db",by="kworker"} 0.5`,
		`shukra_sched_vcpu_preempted_by_seconds_total{vm="db",by="vm:web"} 3`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, `vm="idle"`) && strings.Contains(text, `shukra_sched_vcpu_preempted_seconds_total{vm="idle"}`) {
		t.Fatalf("a VM the sched program has not measured has no series, not a zero:\n%s", text)
	}
	if strings.Contains(text, "ird") {
		t.Fatalf("a preemptor with no time is not a series:\n%s", text)
	}
}

func TestTheSchedRowAlwaysHasAPreemptorListNotNull(t *testing.T) {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	st.SetCounters(map[uint32]aggregate.Counters{100: {OnCPUNs: 5}})
	body := get(New(st, "k"), "/api/v1/trace/sched", "k").Body.String()
	compact := strings.Join(strings.Fields(body), "")
	if strings.Contains(compact, `"topPreemptors":null`) || !strings.Contains(compact, `"topPreemptors":[]`) {
		t.Fatalf("an empty list must be [] and not null: %s", body)
	}
}

func TestParseAtReadsATimeOrAnAgeAndRefusesTheFutureAndGarbage(t *testing.T) {
	now := time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC)
	ok := map[string]time.Time{
		"2026-09-20T03:12:00Z":      time.Date(2026, 9, 20, 3, 12, 0, 0, time.UTC),
		"2026-09-20T09:12:00+05:30": time.Date(2026, 9, 20, 3, 42, 0, 0, time.UTC),
		"-90m":                      now.Add(-90 * time.Minute),
		"-36h":                      now.Add(-36 * time.Hour),
	}
	for raw, want := range ok {
		got, err := parseAt(raw, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v, want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"yesterday", "90m", "-0s", "+5m", "2026-09-20", "2026-09-21T04:00:00Z", "-abc"} {
		if _, err := parseAt(raw, now); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

func TestParseAtWindowIsFiveMinutesToSixHours(t *testing.T) {
	if d, err := parseAtWindow(""); err != nil || d != state.DefaultAtWindow {
		t.Fatalf("%v %v", d, err)
	}
	for _, raw := range []string{"5m", "90m", "6h"} {
		if _, err := parseAtWindow(raw); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
	for _, raw := range []string{"4m59s", "6h1s", "0", "lifetime", "x"} {
		if _, err := parseAtWindow(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestExplainAtAnswersFromHistoryOrSaysThereIsNone(t *testing.T) {
	h := New(state.New("node-07"), "k")
	rec := get(h, "/api/v1/explain?vm=db&at=-1h", "k")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var ex struct {
		At       string `json:"at"`
		Window   string `json:"window"`
		Findings []struct {
			Cause string `json:"cause"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ex); err != nil {
		t.Fatal(err)
	}
	if len(ex.Findings) != 1 || ex.Findings[0].Cause != "no_history" || ex.At == "" || ex.Window != "none" {
		t.Fatalf("%s", rec.Body.String())
	}
	for _, bad := range []string{"at=tomorrow", "at=-1h&window=1m", "at=-1h&window=lifetime"} {
		if rec := get(h, "/api/v1/explain?vm=db&"+bad, "k"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	// Without at it is still the live verdict, with the old window rules.
	if rec := get(h, "/api/v1/explain?vm=db&window=lifetime", "k"); rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	if rec := get(h, "/api/v1/explain?vm=db&window=1h", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a live window is still at most five minutes: %d", rec.Code)
	}
}

func TestIncidentNeedsAVMAndReturnsTheWholeBundle(t *testing.T) {
	st := state.New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	h := New(st, "k")
	if rec := get(h, "/api/v1/incident", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d", rec.Code)
	}
	if rec := get(h, "/api/v1/incident?vm=db&at=soon", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d", rec.Code)
	}
	rec := get(h, "/api/v1/incident?vm=db", "k")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	body := strings.Join(strings.Fields(rec.Body.String()), "")
	for _, want := range []string{`"product":"shukra"`, `"vm":"db"`, `"at":"now"`, `"detections":[]`, `"events":[]`, `"isolations":[]`, `"allowList":[]`, `"explain":{`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	if rec := get(New(st, "k"), "/api/v1/incident?vm=db", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an incident bundle needs the key: %d", rec.Code)
	}
}

func TestContentionEndpointServesPairsVictimsAndCulpritsAndNeverNull(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/trace/contention", "k").Body.String()), "")
	for _, want := range []string{`"pairs":[]`, `"victims":[]`, `"culprits":[]`, `"window":"lifetime"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s: %s", want, body)
		}
	}
	st.SetVMs([]identity.VM{
		{Name: "a", PID: 100, Threads: []int{100, 101}}, {Name: "b", PID: 200, Threads: []int{200, 201}},
	})
	st.SetCounters(map[uint32]aggregate.Counters{
		101: {OnCPUNs: 1, WakeupCount: 1, PreemptNs: 800_000_000, PreemptCount: 4, Preemptors: map[string]uint64{"vm:b": 800_000_000}},
		201: {OnCPUNs: 5, WakeupCount: 1},
	})
	var got struct {
		Pairs []struct {
			Victim, Culprit string
			PreemptedNs     uint64
			Share           float64
		} `json:"pairs"`
	}
	rec := get(h, "/api/v1/trace/contention?vm=a", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Pairs) != 1 || got.Pairs[0].Culprit != "b" || got.Pairs[0].Share != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if rec := get(h, "/api/v1/trace/contention?window=1h", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a window over five minutes is refused: %d", rec.Code)
	}
	if rec := get(h, "/api/v1/trace/contention", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestParseAdviceWindowIsOneToFiveMinutes(t *testing.T) {
	if d, err := parseAdviceWindow(""); err != nil || d != state.DefaultAdviceWindow {
		t.Fatalf("%v %v", d, err)
	}
	for _, ok := range []string{"1m", "90s", "5m"} {
		if _, err := parseAdviceWindow(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"59s", "5m1s", "0", "lifetime", "x"} {
		if _, err := parseAdviceWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAdviceEndpointHasAWindowANoteAndListsThatAreNeverNull(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/advice", "k").Body.String()), "")
	for _, want := range []string{`"rows":[]`, `"window":"5m0s"`, `"note":"Adviceforaperson,neveranaction.`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100}}})
	body = strings.Join(strings.Fields(get(h, "/api/v1/advice?vm=db", "k").Body.String()), "")
	for _, want := range []string{`"vm":"db"`, `"kind":"not_enough_data"`, `"evidence":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	if rec := get(h, "/api/v1/advice?window=10m", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("%d", rec.Code)
	}
	if rec := get(h, "/api/v1/advice", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

// baseView is a state.BaselineView over a real store.
type baseView struct {
	s                  *baseline.Store
	enabled, persisted bool
}

func (v baseView) Enabled() bool             { return v.enabled }
func (v baseView) Persisted() bool           { return v.persisted }
func (v baseView) Options() baseline.Options { return v.s.Options() }
func (v baseView) Status(vm string, now time.Time) []baseline.VMStatus {
	return v.s.Status(vm, now)
}
func (v baseView) Items(vm string, limit int) []baseline.Learned { return v.s.Items(vm, limit) }
func (v baseView) Forget(vm string) bool                         { return v.s.Forget(vm) }

func post(h http.Handler, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("X-Shukra-Actor", "tester")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBaselineEndpointIsOffByDefaultAndListsWhatIsLearnedWhenOn(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/baseline", "k").Body.String()), "")
	for _, want := range []string{`"enabled":false`, `"persisted":false`, `"rows":[]`, `"items":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	store := baseline.NewStore(baseline.Options{Learn: time.Hour})
	store.Observe("web", baseline.Destination, "203.0.113.0/24", time.Now().Add(-10*time.Minute))
	store.Observe("db", baseline.DNSSuffix, "example.com", time.Now().Add(-10*time.Minute))
	st.SetBaselines(baseView{s: store, enabled: true, persisted: true})
	var got struct {
		Enabled, Persisted bool
		Learn              string
		Rows               []struct {
			VM       string
			Learning bool
		}
		Items []struct{ Kind, Item string }
	}
	rec := get(h, "/api/v1/baseline", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !got.Enabled || !got.Persisted || got.Learn != "1h0m0s" || len(got.Rows) != 2 || !got.Rows[0].Learning {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if len(got.Items) != 0 {
		t.Fatalf("items are only listed for one VM that asks: %+v", got.Items)
	}
	rec = get(h, "/api/v1/baseline?vm=web&items=1", "k")
	got.Items = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Rows) != 1 || len(got.Items) != 1 || got.Items[0].Item != "203.0.113.0/24" {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if strings.Contains(get(h, "/api/v1/baseline?vm=nobody&items=1", "k").Body.String(), "null") {
		t.Fatal("an unknown VM is [] and never null")
	}
	if rec := get(h, "/api/v1/baseline", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestForgettingABaselineNeedsTheAdminKeyAndIsRecordedAsADetection(t *testing.T) {
	st := state.New("node-07")
	store := baseline.NewStore(baseline.Options{Learn: time.Hour})
	store.Observe("web", baseline.Destination, "x", time.Now())
	h := NewWithKeys(st, Keys{Admin: "admin", ReadOnly: "ro"})
	if rec := post(h, "/api/v1/baseline/forget", "admin", `{"vm":"web"}`); rec.Code != http.StatusConflict {
		t.Fatalf("with baselines off: %d", rec.Code)
	}
	st.SetBaselines(baseView{s: store, enabled: true, persisted: true})
	if rec := post(h, "/api/v1/baseline/forget", "ro", `{"vm":"web"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("a read-only key must not reset what a VM has learned: %d", rec.Code)
	}
	if len(store.Items("web", 0)) != 1 {
		t.Fatal("a refused request changed the baseline")
	}
	for _, bad := range []string{`{}`, `not json`, `{"vm":""}`} {
		if rec := post(h, "/api/v1/baseline/forget", "admin", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", bad, rec.Code)
		}
	}
	if rec := post(h, "/api/v1/baseline/forget", "admin", `{"vm":"nobody"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("%d", rec.Code)
	}
	if rec := post(h, "/api/v1/baseline/forget", "admin", `{"vm":"web"}`); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if store.Items("web", 0) != nil {
		t.Fatal("it was not forgotten")
	}
	var found bool
	for _, d := range st.Detections("web") {
		if d.Rule == "baseline-forgotten" && strings.Contains(d.Message, "tester") {
			found = true
		}
	}
	if !found {
		t.Fatalf("forgetting hides a change, so it must leave a record naming who: %+v", st.Detections("web"))
	}
}

func TestMetricsShowBaselinesOnlyWhenTheyAreOn(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_baseline_") {
		t.Fatal("series for something that is off")
	}
	store := baseline.NewStore(baseline.Options{Learn: time.Hour, MaxAlertsPerDay: 1})
	store.Observe("web", baseline.Destination, "a", time.Now().Add(-3*time.Hour))
	store.Observe("web", baseline.Destination, "b", time.Now())
	store.Observe("web", baseline.Destination, "c", time.Now())
	st.SetBaselines(baseView{s: store, enabled: true, persisted: true})
	text := get(h, "/metrics", "k").Body.String()
	for _, want := range []string{
		`shukra_baseline_learning{vm="web"} 0`,
		`shukra_baseline_items{vm="web",kind="destination"} 3`,
		`shukra_baseline_items{vm="web",kind="dns-suffix"} 0`,
		`shukra_baseline_new_total{vm="web"} 1`,
		`shukra_baseline_suppressed_total{vm="web"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
}

// The agent always gives the state a view; whether the rules file has baselines on is the view's to say.
func TestAViewWhoseRulesHaveBaselinesOffIsOffEverywhere(t *testing.T) {
	st := state.New("node-07")
	store := baseline.NewStore(baseline.Options{Learn: time.Hour})
	store.Observe("web", baseline.Destination, "x", time.Now().Add(-3*time.Hour)) // learned while it was on
	st.SetBaselines(baseView{s: store, enabled: false, persisted: true})
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/baseline?vm=web&items=1", "k").Body.String()), "")
	if !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, `"rows":[]`) || !strings.Contains(body, `"items":[]`) {
		t.Fatalf("what was learned earlier is not shown while it is off: %s", body)
	}
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_baseline_") {
		t.Fatal("series for baselines that are off")
	}
	if rec := post(h, "/api/v1/baseline/forget", "k", `{"vm":"web"}`); rec.Code != http.StatusConflict {
		t.Fatalf("%d", rec.Code)
	}
	if len(store.Items("web", 0)) != 1 {
		t.Fatal("a refused forget changed the baseline")
	}
}

// actionsView is a state.ActionsView with a list and recorded decisions.
type actionsView struct {
	enabled bool
	list    []state.Action
	actor   string
	verb    string
	err     error
	bundle  []byte
}

func (v *actionsView) Enabled() bool { return v.enabled }
func (v *actionsView) List(all bool) []state.Action {
	if all {
		return v.list
	}
	var out []state.Action
	for _, a := range v.list {
		if a.Status == "pending" {
			out = append(out, a)
		}
	}
	return out
}
func (v *actionsView) decide(verb, id, actor string) (state.Action, error) {
	v.verb, v.actor = verb, actor
	for _, a := range v.list {
		if a.ID == id {
			if v.err != nil {
				return a, v.err
			}
			a.Status = map[string]string{"approve": "executed", "reject": "rejected"}[verb]
			return a, nil
		}
	}
	return state.Action{}, state.ErrActionNotFound
}
func (v *actionsView) Approve(id, actor string) (state.Action, error) {
	return v.decide("approve", id, actor)
}
func (v *actionsView) Reject(id, actor string) (state.Action, error) {
	return v.decide("reject", id, actor)
}
func (v *actionsView) Bundle(id string) ([]byte, bool) {
	if id == "a-1" {
		return v.bundle, true
	}
	return nil, false
}
func (v *actionsView) Counts() map[string]int {
	c := map[string]int{}
	for _, a := range v.list {
		c[a.Status]++
	}
	return c
}
func (v *actionsView) Modes() (int, int, int) { return 1, 0, 0 }

func TestActionsEndpointIsEmptyWhenThereAreNoResponsesAndListsWhatWasDecided(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/actions", "k").Body.String()), "")
	for _, want := range []string{`"enabled":false`, `"pending":0`, `"actions":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	v := &actionsView{enabled: true, list: []state.Action{{ID: "a-3", VM: "web", Status: "executed"}, {ID: "a-2", VM: "web", Status: "executed"}, {ID: "a-1", VM: "db", Status: "pending"}}}
	st.SetActions(v)
	var got struct {
		Enabled bool
		Pending int
		Actions []struct{ ID, Status string }
	}
	rec := get(h, "/api/v1/actions", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !got.Enabled || got.Pending != 1 || len(got.Actions) != 1 || got.Actions[0].ID != "a-1" {
		t.Fatalf("by default only what waits for a person: %v %s", err, rec.Body.String())
	}
	rec = get(h, "/api/v1/actions?all=1", "k")
	got.Actions = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Actions) != 3 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if rec := get(h, "/api/v1/actions", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestOnlyTheAdminKeyDecidesAndTheActorIsPassedOn(t *testing.T) {
	st := state.New("node-07")
	v := &actionsView{enabled: true, list: []state.Action{{ID: "a-1", VM: "web", Status: "pending"}}}
	st.SetActions(v)
	h := NewWithKeys(st, Keys{Admin: "admin", ReadOnly: "ro"})
	for _, path := range []string{"/api/v1/actions/a-1/approve", "/api/v1/actions/a-1/reject"} {
		if rec := post(h, path, "ro", ""); rec.Code != http.StatusForbidden {
			t.Fatalf("a read-only key must not isolate a VM: %s %d", path, rec.Code)
		}
	}
	if v.verb != "" {
		t.Fatal("a refused request reached the engine")
	}
	rec := post(h, "/api/v1/actions/a-1/approve", "admin", "")
	if rec.Code != 200 || v.verb != "approve" || !strings.Contains(v.actor, "admin:") || !strings.Contains(v.actor, "label=tester") || !strings.Contains(rec.Body.String(), `"executed"`) {
		t.Fatalf("%d %s %+v", rec.Code, rec.Body.String(), v)
	}
	rec = post(h, "/api/v1/actions/a-1/reject", "admin", "")
	if rec.Code != 200 || v.verb != "reject" || !strings.Contains(rec.Body.String(), `"rejected"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec := post(h, "/api/v1/actions/a-9/approve", "admin", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("%d", rec.Code)
	}
}

func TestADecisionTheGuardrailsRefuseIsAConflictThatCarriesTheActionAndTheReason(t *testing.T) {
	st := state.New("node-07")
	v := &actionsView{enabled: true, list: []state.Action{{ID: "a-1", VM: "web", Status: "refused", Result: "web is protected"}}, err: state.ErrActionNotPending}
	st.SetActions(v)
	h := New(st, "k")
	rec := post(h, "/api/v1/actions/a-1/approve", "k", "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "not waiting for a decision") || !strings.Contains(rec.Body.String(), "web is protected") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	v.err = errors.New("web is protected: no response may isolate it")
	rec = post(h, "/api/v1/actions/a-1/approve", "k", "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no response may isolate it") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	st2 := state.New("node-07")
	if rec := post(New(st2, "k"), "/api/v1/actions/a-1/approve", "k", ""); rec.Code != http.StatusConflict {
		t.Fatalf("with no responses configured there is nothing to decide: %d", rec.Code)
	}
}

func TestTheIncidentBundleOfAnActionIsServedAsIsAndUnknownIdsAreNotFound(t *testing.T) {
	st := state.New("node-07")
	st.SetActions(&actionsView{enabled: true, bundle: []byte(`{"vm":"web","note":"n"}`)})
	h := New(st, "k")
	rec := get(h, "/api/v1/actions/a-1/incident", "k")
	if rec.Code != 200 || rec.Body.String() != `{"vm":"web","note":"n"}` || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	if rec := get(h, "/api/v1/actions/a-2/incident", "k"); rec.Code != http.StatusNotFound {
		t.Fatalf("%d", rec.Code)
	}
	if rec := get(h, "/api/v1/actions/a-1/incident", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestMetricsShowActionsOnlyWhenResponsesAreConfigured(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_actions") {
		t.Fatal("series for something that is off")
	}
	st.SetActions(&actionsView{enabled: true, list: []state.Action{{ID: "a-1", Status: "pending"}, {ID: "a-2", Status: "executed"}, {ID: "a-3", Status: "executed"}}})
	text := get(h, "/metrics", "k").Body.String()
	for _, want := range []string{"shukra_actions_pending 1", `shukra_actions{status="executed"} 2`, `shukra_actions{status="refused"} 0`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
}

func TestDecidingWhenNoResponsesAreConfiguredIsAConflictAndReachesNothing(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	if rec := post(h, "/api/v1/actions/a-1/approve", "k", ""); rec.Code != http.StatusConflict {
		t.Fatalf("nothing configured: %d", rec.Code)
	}
	v := &actionsView{enabled: false, list: []state.Action{{ID: "a-1", Status: "pending"}}}
	st.SetActions(v)
	for _, verb := range []string{"approve", "reject"} {
		if rec := post(h, "/api/v1/actions/a-1/"+verb, "k", ""); rec.Code != http.StatusConflict || v.verb != "" {
			t.Fatalf("a view with no responses must not decide: %s %d %+v", verb, rec.Code, v)
		}
	}
}

func TestADecisionWithoutAnActorHeaderIsRecordedAsTheAPI(t *testing.T) {
	st := state.New("node-07")
	v := &actionsView{enabled: true, list: []state.Action{{ID: "a-1", VM: "web", Status: "pending"}}}
	st.SetActions(v)
	h := New(st, "k")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/actions/a-1/approve", nil)
	req.Header.Set("Authorization", "Bearer k")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(v.actor, "key=admin:") {
		t.Fatalf("who decided must never be empty: %d %q", rec.Code, v.actor)
	}
}

func TestMetricsShowNothingForAViewWithNoResponses(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	st.SetActions(&actionsView{enabled: false, list: []state.Action{{ID: "a-1", Status: "pending"}}})
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_actions") {
		t.Fatal("series for responses that are not configured")
	}
}

type policyFake struct {
	rows      []state.PolicyRow
	orphans   []state.PolicyOrphan
	persisted bool
	err       error
	// what the last request was
	verb, vm, actor string
	req             state.PolicyRequest
}

func (p *policyFake) List() []state.PolicyRow { return p.rows }
func (p *policyFake) Get(vm string) (state.PolicyRow, bool) {
	for _, r := range p.rows {
		if r.VM == vm {
			return r, true
		}
	}
	return state.PolicyRow{}, false
}
func (p *policyFake) Learn(vm string) (state.PolicyProposal, error) {
	p.verb, p.vm = "learn", vm
	if p.err != nil {
		return state.PolicyProposal{}, p.err
	}
	return state.PolicyProposal{VM: vm, Allow: []string{"203.0.113.0/24"}, Current: []string{}, Added: []string{"203.0.113.0/24"}, Removed: []string{}}, nil
}
func (p *policyFake) done(verb, vm, actor string) (state.PolicyRow, error) {
	p.verb, p.vm, p.actor = verb, vm, actor
	if p.err != nil {
		return state.PolicyRow{}, p.err
	}
	return state.PolicyRow{VM: vm, Mode: "audit", Allow: []string{}, Taps: []state.PolicyTap{}}, nil
}
func (p *policyFake) Apply(vm string, req state.PolicyRequest, actor string) (state.PolicyRow, error) {
	p.req = req
	return p.done("apply", vm, actor)
}
func (p *policyFake) Confirm(vm, actor string) (state.PolicyRow, error) {
	return p.done("confirm", vm, actor)
}
func (p *policyFake) Remove(vm, actor string) (state.PolicyRow, error) {
	return p.done("remove", vm, actor)
}
func (p *policyFake) Orphans() []state.PolicyOrphan { return p.orphans }
func (p *policyFake) Persisted() bool               { return p.persisted }

func TestThePolicyEndpointIsEmptyWithoutAnEngineAndListsWhatThereIsWithOne(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	body := strings.Join(strings.Fields(get(h, "/api/v1/policy", "k").Body.String()), "")
	for _, want := range []string{`"enabled":false`, `"persisted":false`, `"policies":[]`, `"orphans":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	f := &policyFake{persisted: true, rows: []state.PolicyRow{{VM: "db", Mode: "audit"}, {VM: "web", Mode: "enforce"}}, orphans: []state.PolicyOrphan{{VM: "x", Tap: "tapx", Mode: "enforce"}}}
	st.SetPolicy(f)
	var got struct {
		Enabled, Persisted bool
		Policies           []struct{ VM, Mode string }
		Orphans            []struct{ VM, Tap, Mode string }
	}
	rec := get(h, "/api/v1/policy", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !got.Enabled || !got.Persisted || len(got.Policies) != 2 || len(got.Orphans) != 1 || got.Orphans[0].Tap != "tapx" {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	got.Policies = nil
	rec = get(h, "/api/v1/policy?vm=web", "k")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Policies) != 1 || got.Policies[0].Mode != "enforce" {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if body := strings.Join(strings.Fields(get(h, "/api/v1/policy?vm=nobody", "k").Body.String()), ""); !strings.Contains(body, `"policies":[]`) {
		t.Fatalf("a VM with no policy is an empty list, not null: %s", body)
	}
	if rec := get(h, "/api/v1/policy", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("%d", rec.Code)
	}
}

func TestOnlyTheAdminKeyChangesAPolicyAndTheRequestAndActorReachTheEngine(t *testing.T) {
	st := state.New("node-07")
	f := &policyFake{}
	st.SetPolicy(f)
	h := NewWithKeys(st, Keys{Admin: "admin", ReadOnly: "ro"})
	for _, path := range []string{"/api/v1/policy/apply", "/api/v1/policy/confirm", "/api/v1/policy/remove"} {
		if rec := post(h, path, "ro", `{"vm":"web","mode":"audit"}`); rec.Code != http.StatusForbidden {
			t.Fatalf("a read-only key must not change a policy: %s %d", path, rec.Code)
		}
	}
	if f.verb != "" {
		t.Fatal("a refused request reached the engine")
	}
	rec := post(h, "/api/v1/policy/apply", "admin", `{"vm":"web","mode":"enforce","allow":["203.0.113.0/24","10.0.0.1"],"fromBaseline":true,"confirm":"5m","permanent":false}`)
	if rec.Code != 200 || f.verb != "apply" || f.vm != "web" || !strings.Contains(f.actor, "admin:") || !strings.Contains(f.actor, "label=tester") || !strings.Contains(rec.Body.String(), `"policy"`) {
		t.Fatalf("%d %s %+v", rec.Code, rec.Body.String(), f)
	}
	if f.req.Mode != "enforce" || !reflect.DeepEqual(f.req.Allow, []string{"203.0.113.0/24", "10.0.0.1"}) || !f.req.FromBaseline || f.req.Confirm != "5m" || f.req.Permanent {
		t.Fatalf("the request arrived as %+v", f.req)
	}
	for verb := range map[string]bool{"confirm": true, "remove": true} {
		if rec := post(h, "/api/v1/policy/"+verb, "admin", `{"vm":"db"}`); rec.Code != 200 || f.verb != verb || f.vm != "db" {
			t.Fatalf("%s: %d %+v", verb, rec.Code, f)
		}
	}
	// without an actor header, the API is the actor
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy/remove", strings.NewReader(`{"vm":"db"}`))
	req.Header.Set("Authorization", "Bearer admin")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.HasPrefix(f.actor, "key=admin:") || strings.Contains(f.actor, "label=") {
		t.Fatalf("who acted must never be empty: %q", f.actor)
	}
}

func TestAPolicyRequestNeedsAVMAndAnEngine(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	if rec := post(h, "/api/v1/policy/apply", "k", `{"vm":"web","mode":"audit"}`); rec.Code != http.StatusConflict {
		t.Fatalf("no engine: %d", rec.Code)
	}
	st.SetPolicy(&policyFake{})
	for _, body := range []string{`{}`, `{"mode":"audit"}`, `not json`, ``} {
		if rec := post(h, "/api/v1/policy/apply", "k", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: %d", body, rec.Code)
		}
	}
	if rec := get(h, "/api/v1/policy/proposal", "k"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a proposal needs a vm: %d", rec.Code)
	}
}

func TestEachKindOfPolicyFailureHasItsOwnStatusAndKeepsItsReason(t *testing.T) {
	st := state.New("node-07")
	f := &policyFake{}
	st.SetPolicy(f)
	h := New(st, "k")
	for _, tc := range []struct {
		err  error
		code int
	}{
		{fmt.Errorf("%w: no VM named x", state.ErrPolicyNotFound), http.StatusNotFound},
		{fmt.Errorf("%w: mode is wrong", state.ErrPolicyBad), http.StatusBadRequest},
		{fmt.Errorf("%w: enforcing needs a floor", state.ErrPolicyRefused), http.StatusConflict},
		{errors.New("disk on fire"), http.StatusInternalServerError},
	} {
		f.err = tc.err
		for _, rec := range []*httptest.ResponseRecorder{post(h, "/api/v1/policy/apply", "k", `{"vm":"web","mode":"audit"}`), get(h, "/api/v1/policy/proposal?vm=web", "k")} {
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), strings.TrimPrefix(tc.err.Error(), "")) {
				t.Fatalf("%v: %d %q", tc.err, rec.Code, rec.Body.String())
			}
		}
	}
	f.err = nil
	rec := get(h, "/api/v1/policy/proposal?vm=web", "k")
	if rec.Code != 200 || f.verb != "learn" || f.vm != "web" || !strings.Contains(rec.Body.String(), "203.0.113.0/24") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestMetricsShowEgressPolicyOnlyForVMsThatHaveOne(t *testing.T) {
	st := state.New("node-07")
	h := New(st, "k")
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_egress") {
		t.Fatal("series for something that is off")
	}
	st.SetPolicy(&policyFake{})
	if strings.Contains(get(h, "/metrics", "k").Body.String(), "shukra_egress") {
		t.Fatal("an engine with no policies has no series")
	}
	st.SetPolicy(&policyFake{rows: []state.PolicyRow{
		{VM: "web", Mode: "audit", Taps: []state.PolicyTap{{Tap: "tapweb", Kernel: "audit", Checked: 40, AuditPkts: 7, AuditBytes: 700}}},
		{VM: "db", Mode: "enforce", Revert: &state.PolicyRevert{Until: time.Now()}, Taps: []state.PolicyTap{{Tap: "tapdb1", Kernel: "enforce", DroppedPkts: 3, DroppedBytes: 300}, {Tap: "tapdb2", Kernel: "off"}}},
	}})
	text := get(h, "/metrics", "k").Body.String()
	for _, want := range []string{
		`shukra_egress_policy_mode{vm="web",tap="tapweb"} 1`, `shukra_egress_policy_mode{vm="db",tap="tapdb1"} 2`, `shukra_egress_policy_mode{vm="db",tap="tapdb2"} 0`,
		`shukra_egress_policy_unconfirmed{vm="web"} 0`, `shukra_egress_policy_unconfirmed{vm="db"} 1`,
		`shukra_egress_checked_total{vm="web",tap="tapweb"} 40`,
		`shukra_egress_audit_packets_total{vm="web",tap="tapweb"} 7`, `shukra_egress_audit_bytes_total{vm="web",tap="tapweb"} 700`,
		`shukra_egress_dropped_packets_total{vm="db",tap="tapdb1"} 3`, `shukra_egress_dropped_bytes_total{vm="db",tap="tapdb1"} 300`,
		"# TYPE shukra_egress_dropped_packets_total counter", "# TYPE shukra_egress_policy_mode gauge",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
}
