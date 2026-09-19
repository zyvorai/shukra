package observe

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DropCounters is what the kernel dropped on one VM tap for one reason, as skb:kfree_skb reported
// it. This is the kernel's count of packets it threw away, whoever asked: Shukra's own isolation
// shows up here as TC_INGRESS or TC_EGRESS, so DroppedPkts on the tap is the part that is Shukra's.
type DropCounters struct {
	Tap      string
	Ifindex  uint32
	Code     uint32
	Reason   string // for example TC_INGRESS, FULL_RING, or "reason 95" when this kernel's names are unknown
	Count    uint64
	Location string // the kernel function that freed the last one, or its address when it cannot be resolved
}

const dropReasonPrefix = "SKB_DROP_REASON_"

// dropReasonLabel is the name to show for a reason code: the kernel's own name without its prefix,
// or the number when this kernel's names could not be read. A name is never guessed.
func dropReasonLabel(names map[uint32]string, code uint32) string {
	if n, ok := names[code]; ok && n != "" {
		return strings.TrimPrefix(n, dropReasonPrefix)
	}
	return fmt.Sprintf("reason %d", code)
}

// nearestSymbol finds the kernel function containing addr in the text of /proc/kallsyms: the
// highest text symbol at or below it. It says false when the file shows only zero addresses, which
// is what a process without CAP_SYSLOG sees while kptr_restrict hides them.
func nearestSymbol(r io.Reader, addr uint64) (string, bool) {
	var best string
	var bestAddr uint64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || (f[1] != "T" && f[1] != "t") {
			continue
		}
		a, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil || a == 0 || a > addr {
			continue
		}
		if a > bestAddr {
			best, bestAddr = f[2], a
		}
	}
	if bestAddr == 0 {
		return "", false
	}
	return best, true
}

func locationLabel(sym string, ok bool, addr uint64) string {
	switch {
	case addr == 0:
		return ""
	case ok:
		return sym
	}
	return fmt.Sprintf("%#x", addr)
}
