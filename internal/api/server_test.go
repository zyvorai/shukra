package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
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
