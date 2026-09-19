package bpfgen

import (
	"strings"
	"testing"
)

func TestTheFunctionNameTheKernelWroteIsReadUpToItsNul(t *testing.T) {
	buf := make([]byte, 48)
	copy(buf, "__netif_receive_skb_core")
	if got := symbolText(buf); got != "__netif_receive_skb_core" {
		t.Fatalf("%q", got)
	}
	if got := symbolText(make([]byte, 48)); got != "" {
		t.Fatalf("nothing written must be empty, not spaces or NULs: %q", got)
	}
	// A buffer that is not a name is not shown as one.
	junk := make([]byte, 48)
	copy(junk, "ok\x01\xffgarbage")
	if got := symbolText(junk); got != "" {
		t.Fatalf("garbage was shown as a name: %q", got)
	}
	// A name that fills the buffer with no NUL is still read, not lost.
	full := []byte(strings.Repeat("a", 48))
	if got := symbolText(full); len(got) != 48 {
		t.Fatalf("%q", got)
	}
}
