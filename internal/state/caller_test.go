package state

import "testing"

func TestActorRoundTrip(t *testing.T) {
	in := Caller{KeyID: "admin:f72c1a", Role: "admin", Label: "shukractl", Remote: "127.0.0.1:9", RequestID: "abc", Op: "isolate"}
	got := ParseActor(EncodeActor(in))
	if got.KeyID != in.KeyID || got.Role != in.Role || got.Label != in.Label || got.Remote != in.Remote || got.RequestID != in.RequestID || got.Op != in.Op {
		t.Fatalf("%+v", got)
	}
	if got.Principal() != "admin:f72c1a (shukractl)" {
		t.Fatalf("principal %q", got.Principal())
	}
	plain := ParseActor("alice")
	if plain.Principal() != "alice" || plain.KeyID != "" {
		t.Fatalf("%+v", plain)
	}
}
