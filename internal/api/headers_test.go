package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecureHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := SecureHeaders(next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, k := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy"} {
		if rr.Header().Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("nosniff: %q", rr.Header().Get("X-Content-Type-Options"))
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("frame: %q", rr.Header().Get("X-Frame-Options"))
	}
	if strings.Contains(rr.Header().Get("Content-Security-Policy"), "http:") {
		t.Errorf("csp should not open remote origins: %s", rr.Header().Get("Content-Security-Policy"))
	}
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be set on plain HTTP")
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://shukra.example/", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Fatalf("HSTS: %q", rr.Header().Get("Strict-Transport-Security"))
	}
}
