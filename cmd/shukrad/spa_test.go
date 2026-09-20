package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSpaStaysInsideTheConsoleDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("index"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("app"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := spa(dir)
	for _, path := range []string{"/", "/index.html", "/../secret.txt", "/%2e%2e/secret.txt", "/app.js/../../secret.txt"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if body := rr.Body.String(); body == "secret" {
			t.Fatalf("%s served a file outside the console directory", path)
		}
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rr.Body.String() != "app" || rr.Code != http.StatusOK {
		t.Fatalf("app.js: %d %q", rr.Code, rr.Body.String())
	}
}
