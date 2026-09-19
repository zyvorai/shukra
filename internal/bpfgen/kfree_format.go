package bpfgen

import (
	"fmt"
	"strconv"
	"strings"
)

// kfreeSkbLayout is where bpf/drops.bpf.c reads each field of skb:kfree_skb. The record is not in
// vmlinux BTF on some kernels, so the program spells it out, and the loader checks the running
// kernel's format file against this before it attaches anything.
var kfreeSkbLayout = []struct {
	name   string
	offset int
}{
	{"skbaddr", 8},
	{"location", 16},
	{"protocol", 24},
	{"reason", 28},
}

// checkKfreeSkbFormat reads the text of /sys/kernel/tracing/events/skb/kfree_skb/format and says
// why the drops program cannot run on this kernel, or nil when the layout is the one it expects.
func checkKfreeSkbFormat(text string) error {
	offsets := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "field:") {
			continue
		}
		parts := strings.Split(line, ";")
		decl := strings.Fields(strings.TrimPrefix(parts[0], "field:"))
		if len(decl) == 0 {
			continue
		}
		name := decl[len(decl)-1]
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if v, ok := strings.CutPrefix(p, "offset:"); ok {
				if n, err := strconv.Atoi(v); err == nil {
					offsets[name] = n
				}
			}
		}
	}
	if len(offsets) == 0 {
		return fmt.Errorf("skb:kfree_skb has no readable format")
	}
	if _, ok := offsets["reason"]; !ok {
		return fmt.Errorf("this kernel's skb:kfree_skb has no drop reason (it needs Linux 5.17 or newer)")
	}
	for _, f := range kfreeSkbLayout {
		got, ok := offsets[f.name]
		if !ok {
			return fmt.Errorf("skb:kfree_skb has no %s field", f.name)
		}
		if got != f.offset {
			return fmt.Errorf("skb:kfree_skb has %s at offset %d, the drops program expects %d", f.name, got, f.offset)
		}
	}
	return nil
}
