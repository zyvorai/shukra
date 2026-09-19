package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/state"
)

// New serves the API behind a bearer key. An empty key fails closed: every
// request is refused. Use NewNoAuth to serve without a key on purpose.
// Isolate records a decision and does not attach a program.
func New(st *state.State, apiKey string) http.Handler {
	return NewWithKeys(st, Keys{Admin: apiKey})
}

// Keys are the bearer keys the API accepts. Admin may do everything. ReadOnly may
// only read, so a monitoring scrape can hold a key that cannot call isolate.
// An empty key never matches.
type Keys struct {
	Admin    string
	ReadOnly string
}

// NewWithKeys serves the API with an admin key and, optionally, a read-only key.
func NewWithKeys(st *state.State, k Keys) http.Handler {
	return auth(k, routes(st))
}

// NewNoAuth serves the API with no bearer check. Only /healthz and /readyz are
// reachable without a key under New; here everything is.
func NewNoAuth(st *state.State) http.Handler {
	return routes(st)
}

func routes(st *state.State) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		s := st.Status()
		code := http.StatusOK
		if !st.Ready() {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]any{
			"ready": st.Ready(), "programsAttached": s.ProgramsAttached, "programsTotal": s.ProgramsTotal,
		})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetrics(w, st)
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.Status())
	})
	mux.HandleFunc("GET /api/v1/vms", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"vms": st.VMs()})
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		since, err := parseSince(r.URL.Query().Get("since"))
		if err != nil {
			http.Error(w, "since must be an unsigned integer", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"seq": st.Seq(), "events": st.EventsSince(r.URL.Query().Get("vm"), since)})
	})
	mux.HandleFunc("GET /api/v1/stream", func(w http.ResponseWriter, r *http.Request) {
		since, err := parseSince(r.URL.Query().Get("since"))
		if err == nil && since == 0 {
			since, err = parseSince(r.Header.Get("Last-Event-ID"))
		}
		if err != nil {
			http.Error(w, "since must be an unsigned integer", http.StatusBadRequest)
			return
		}
		stream(w, r, st, r.URL.Query().Get("vm"), since)
	})
	mux.HandleFunc("GET /api/v1/doctor", func(w http.ResponseWriter, r *http.Request) {
		checks := st.Doctor()
		worst := "ok"
		for _, c := range checks {
			if c.Status == "fail" || (c.Status == "warn" && worst != "fail") || (c.Status == "info" && worst == "ok") {
				worst = c.Status
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"worst": worst, "checks": checks})
	})
	mux.HandleFunc("GET /api/v1/isolations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"isolations": st.Isolations()})
	})
	mux.HandleFunc("GET /api/v1/detections", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"detections": st.Detections(r.URL.Query().Get("vm"))})
	})
	mux.HandleFunc("GET /api/v1/recorder", func(w http.ResponseWriter, r *http.Request) {
		window := 60 * time.Second
		if raw := r.URL.Query().Get("window"); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil && d > 0 {
				window = d
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"window": window.String(),
			"events": st.Recorder(r.URL.Query().Get("vm"), window, time.Now().UTC()),
		})
	})
	mux.HandleFunc("GET /api/v1/programs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"programs": st.Programs()})
	})
	mux.HandleFunc("GET /api/v1/trace/kvm", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"rows": st.KVM(r.URL.Query().Get("vm"))})
	})
	mux.HandleFunc("GET /api/v1/trace/sched", func(w http.ResponseWriter, r *http.Request) {
		vm := r.URL.Query().Get("vm")
		out := map[string]any{"rows": st.Sched(vm)}
		if r.URL.Query().Get("threads") == "1" {
			out["threads"] = st.SchedThreads(vm)
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /api/v1/trace/block", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"rows": st.Block(r.URL.Query().Get("vm"))})
	})
	mux.HandleFunc("GET /api/v1/trace/net", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"attribution":     "qemu-process",
			"guestAttributed": false,
			"note":            "These are connects from the QEMU process, not the guest.",
			"rows":            st.Net(r.URL.Query().Get("vm")),
		})
	})
	mux.HandleFunc("GET /api/v1/explain", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.Explain(r.URL.Query().Get("vm"), time.Now().UTC()))
	})
	mux.HandleFunc("GET /api/v1/export", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.Export())
	})
	mux.HandleFunc("GET /api/v1/security", func(w http.ResponseWriter, r *http.Request) {
		vm := r.URL.Query().Get("vm")
		mode, allow, why := st.Enforcement()
		out := map[string]any{"vm": vm, "detections": st.Detections(vm), "enforcement": mode, "allowList": allow, "durable": st.Durable()}
		if why != "" {
			out["reason"] = why
		}
		writeJSON(w, http.StatusOK, out)
	})
	act := func(do func(vm, actor string) state.Isolation) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				VM string `json:"vm"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil || body.VM == "" {
				http.Error(w, "vm is required", http.StatusBadRequest)
				return
			}
			actor := r.Header.Get("X-Shukra-Actor")
			if actor == "" {
				actor = "api"
			}
			writeJSON(w, http.StatusOK, do(body.VM, actor))
		}
	}
	mux.HandleFunc("POST /api/v1/isolate", act(st.Isolate))
	mux.HandleFunc("POST /api/v1/release", act(st.Release))
	mux.HandleFunc("GET /api/v1/trace/tap", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"attribution":     "guest-tap",
			"guestAttributed": true,
			"note":            "Traffic seen on the host side of each VM tap: from_guest is what the guest sent, to_guest is what was sent to it.",
			"rows":            st.Taps(r.URL.Query().Get("vm")),
		})
	})
	return mux
}

func parseSince(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	return strconv.ParseUint(raw, 10, 64)
}

// stream writes events as server-sent events. Each frame's id is the event Seq,
// so a reconnecting client resumes with Last-Event-ID.
func stream(w http.ResponseWriter, r *http.Request, st *state.State, vm string, since uint64) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		changed := st.Changed()
		for _, e := range st.EventsSince(vm, since) {
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %d\nevent: event\ndata: %s\n\n", e.Seq, b)
			since = e.Seq
		}
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-changed:
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

func auth(k Keys, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/"),
			r.URL.Path == "/healthz", r.URL.Path == "/readyz":
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got = strings.TrimSpace(got)
		// Both keys are always compared so the time taken does not say which one matched.
		admin := keyMatches(got, k.Admin)
		readOnly := keyMatches(got, k.ReadOnly)
		if !admin && !readOnly {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if !admin && r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"this key is read-only"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func keyMatches(got, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
