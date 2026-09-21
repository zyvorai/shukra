package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/zyvorai/shukra/internal/state"
)

type principalKey struct{}

type principal struct {
	KeyID     string
	Role      string
	Label     string
	Remote    string
	RequestID string
}

func (p principal) encode(op string) string {
	return state.EncodeActor(state.Caller{
		KeyID: p.KeyID, Role: p.Role, Label: p.Label, Remote: p.Remote, RequestID: p.RequestID, Op: op,
	})
}

func actorOf(r *http.Request, op string) string {
	p, _ := r.Context().Value(principalKey{}).(principal)
	if p.KeyID == "" {
		return "api"
	}
	return p.encode(op)
}

// keyID is role plus the first 6 hex characters of SHA-256(key). It identifies
// which configured key was used without storing or logging the key.
func keyID(role, key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return role + ":" + hex.EncodeToString(sum[:])[:6]
}

func clientLabel(r *http.Request) string {
	s := strings.TrimSpace(r.Header.Get("X-Shukra-Actor"))
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return ""
		}
	}
	return s
}

func requestID(r *http.Request) string {
	s := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if s != "" && len(s) <= 64 && clientLabel(&http.Request{Header: http.Header{"X-Shukra-Actor": []string{s}}}) == s {
		return s
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "none"
	}
	return hex.EncodeToString(b[:])
}

func withPrincipal(r *http.Request, p principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}
