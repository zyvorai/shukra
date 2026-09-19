package api

import (
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
