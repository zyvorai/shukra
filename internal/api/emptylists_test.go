package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

// nulls returns the path of every null in a decoded JSON document.
func nulls(v any, path string, out *[]string) {
	switch x := v.(type) {
	case nil:
		*out = append(*out, path)
	case map[string]any:
		for k, e := range x {
			nulls(e, path+"."+k, out)
		}
	case []any:
		for i, e := range x {
			nulls(e, path+"[]", out)
			_ = i
		}
	}
}

// Every list the API returns is a list when it is empty: a client takes its length or loops over it, and a
// null makes that a special case (development.md, "empty lists are [], never null"). Each GET route is
// asked with nothing known, and again with one VM known that has measured nothing.
func TestEmptyListsAreNeverNull(t *testing.T) {
	routes := []string{
		"/api/v1/status", "/api/v1/vms", "/api/v1/programs", "/api/v1/doctor", "/api/v1/security", "/api/v1/isolations",
		"/api/v1/detections", "/api/v1/detections?vm=vm-a", "/api/v1/events", "/api/v1/events?vm=vm-a",
		"/api/v1/recorder?vm=vm-a", "/api/v1/export", "/api/v1/actions", "/api/v1/advice", "/api/v1/baseline",
		"/api/v1/policy", "/api/v1/policy?vm=vm-a", "/api/v1/trace/kvm", "/api/v1/trace/sched", "/api/v1/trace/sched?threads=1",
		"/api/v1/trace/block", "/api/v1/trace/memory", "/api/v1/trace/net", "/api/v1/trace/tap", "/api/v1/trace/drops", "/api/v1/trace/contention",
		"/api/v1/explain?vm=vm-a", "/api/v1/incident?vm=vm-a",
	}
	for _, withVM := range []bool{false, true} {
		st := state.New("node-07")
		if withVM {
			st.AddEvent(event.Event{Kind: event.KindTCPConnect, TS: time.Now().UTC(), VM: event.VM{Name: "vm-a", UUID: "u", Runtime: "qemu"}})
		}
		h := New(st, "k")
		for _, path := range routes {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer k")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				continue // a route that needs something this state does not have answers with its own error
			}
			var doc any
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				continue // not JSON (metrics-like)
			}
			var bad []string
			nulls(doc, "", &bad)
			sort.Strings(bad)
			if len(bad) > 0 {
				t.Errorf("%s (vm known: %v): null where a list belongs: %s", path, withVM, strings.Join(bad, ", "))
			}
		}
	}
}
