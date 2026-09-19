package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/shukra/internal/state"
)

// New serves the read API. Isolate records a decision and does not attach a program.
func New(st *state.State, apiKey string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, st.Status())
	})
	mux.HandleFunc("GET /api/v1/vms", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"vms": st.VMs()})
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"events": st.Events(r.URL.Query().Get("vm"))})
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
		writeJSON(w, http.StatusOK, map[string]any{"rows": st.Sched(r.URL.Query().Get("vm"))})
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
	mux.HandleFunc("GET /api/v1/security", func(w http.ResponseWriter, r *http.Request) {
		vm := r.URL.Query().Get("vm")
		writeJSON(w, http.StatusOK, map[string]any{
			"vm":          vm,
			"detections":  st.Detections(vm),
			"enforcement": "not_attached",
		})
	})
	mux.HandleFunc("POST /api/v1/isolate", func(w http.ResponseWriter, r *http.Request) {
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
		writeJSON(w, http.StatusOK, st.Isolate(body.VM, actor))
	})
	return auth(apiKey, mux)
}

func auth(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/") {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got = strings.TrimSpace(got)
		if apiKey != "" && got != apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
