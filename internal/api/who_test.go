package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zyvorai/shukra/internal/state"
)

func TestKeyIDIsAStablePrefixAndNotTheKey(t *testing.T) {
	id := keyID("admin", "not-the-prefix")
	if id == "admin:not-th" || len(id) != len("admin:")+6 {
		t.Fatalf("%q", id)
	}
	if keyID("admin", "not-the-prefix") != id {
		t.Fatal("key id changed")
	}
	if keyID("readonly", "not-the-prefix") == id {
		t.Fatal("role is part of the id")
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Shukra-Actor", "shukractl")
	req.Header.Set("X-Request-Id", "req-1")
	req.RemoteAddr = "127.0.0.1:9"
	p := principal{KeyID: id, Role: "admin", Label: clientLabel(req), Remote: req.RemoteAddr, RequestID: requestID(req)}
	got := state.ParseActor(p.encode("isolate"))
	if got.Principal() != id+" (shukractl)" || got.Op != "isolate" || got.RequestID != "req-1" || got.Remote != "127.0.0.1:9" {
		t.Fatalf("%+v", got)
	}
	req.Header.Set("X-Shukra-Actor", "has space")
	if clientLabel(req) != "" {
		t.Fatal("a label with a space must be ignored")
	}
}
