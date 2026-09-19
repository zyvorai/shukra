package bpfgen

import (
	"fmt"
	"strings"
)

// checkKfreeSkbFormat reads the text of /sys/kernel/tracing/events/skb/kfree_skb/format and says why the
// drops program cannot run on this kernel, or nil when it can. The program reads the record through the
// kernel's own type (CO-RE), so where the fields sit does not matter, and it did matter: Linux 6.9 put a new
// field, rx_sk, in front of protocol and reason. What is needed is a drop reason to read at all.
func checkKfreeSkbFormat(text string) error {
	fields := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "field:") {
			continue
		}
		decl := strings.Fields(strings.TrimPrefix(strings.SplitN(line, ";", 2)[0], "field:"))
		if len(decl) > 0 {
			fields[decl[len(decl)-1]] = true
		}
	}
	if len(fields) == 0 {
		return fmt.Errorf("skb:kfree_skb has no readable format")
	}
	if !fields["reason"] {
		return fmt.Errorf("this kernel's skb:kfree_skb has no drop reason (it needs Linux 5.17 or newer)")
	}
	for _, f := range []string{"skbaddr", "location"} {
		if !fields[f] {
			return fmt.Errorf("skb:kfree_skb has no %s field", f)
		}
	}
	return nil
}
