//go:build linux && shukrabpf

package observe

import (
	"net"
	"os"
	"sort"
	"sync"

	"github.com/cilium/ebpf/btf"
	"github.com/zyvorai/shukra/internal/bpfgen"
)

var (
	reasonOnce  sync.Once
	reasonNames map[uint32]string

	symMu    sync.Mutex
	symCache = map[uint64]string{}
)

// kernelDropReasons reads the names of this kernel's skb_drop_reason values from its BTF. The
// numbers change between kernels, so they are never hardcoded. Empty when BTF cannot be read, and
// then a reason is shown as its number.
func kernelDropReasons() map[uint32]string {
	reasonOnce.Do(func() {
		reasonNames = map[uint32]string{}
		spec, err := btf.LoadKernelSpec()
		if err != nil {
			return
		}
		var enum *btf.Enum
		if err := spec.TypeByName("skb_drop_reason", &enum); err != nil {
			return
		}
		for _, v := range enum.Values {
			reasonNames[uint32(v.Value)] = v.Name
		}
	})
	return reasonNames
}

// resolveLocation names the kernel function at an address, once per address. Without CAP_SYSLOG the
// addresses in /proc/kallsyms read as zero, and then the address itself is shown.
func resolveLocation(addr uint64) string {
	if addr == 0 {
		return ""
	}
	symMu.Lock()
	defer symMu.Unlock()
	if s, ok := symCache[addr]; ok {
		return s
	}
	label := locationLabel("", false, addr)
	if f, err := os.Open("/proc/kallsyms"); err == nil {
		sym, ok := nearestSymbol(f, addr)
		f.Close()
		label = locationLabel(sym, ok, addr)
	}
	if len(symCache) > 1024 {
		symCache = map[uint64]string{}
	}
	symCache[addr] = label
	return label
}

// dropLocation is the function that freed the packets. The kernel names it itself when the program
// first sees a reason on a tap, and that needs no capability. Failing that, /proc/kallsyms is tried
// (which needs CAP_SYSLOG to show real addresses), and failing that the address is shown.
func dropLocation(v bpfgen.DropSum) string {
	if v.Symbol != "" {
		return v.Symbol
	}
	return resolveLocation(v.Location)
}

// watchDrops points the drops program at the interfaces the tap program is on.
func watchDrops() {
	var idx []uint32
	for _, name := range bpfgen.TapAttached() {
		if iface, err := net.InterfaceByName(name); err == nil {
			idx = append(idx, uint32(iface.Index))
		}
	}
	bpfgen.SetDropWatch(idx)
}

// DropSample reads what the kernel dropped on each VM tap, by reason.
func DropSample() []DropCounters {
	stats := bpfgen.DropStats()
	if len(stats) == 0 {
		return nil
	}
	names := kernelDropReasons()
	var out []DropCounters
	for k, v := range stats {
		tap := bpfgen.TapName(k.Ifindex)
		if tap == "" {
			continue // an interface this daemon no longer owns
		}
		out = append(out, DropCounters{
			Tap: tap, Ifindex: k.Ifindex, Code: k.Reason, Reason: dropReasonLabel(names, k.Reason),
			Count: v.Count, Location: dropLocation(v),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tap != out[j].Tap {
			return out[i].Tap < out[j].Tap
		}
		return out[i].Count > out[j].Count
	})
	return out
}
