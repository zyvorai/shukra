//go:build linux && shukrabpf

package bpfgen

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// tryDrops attaches the drops program, unless this kernel's skb:kfree_skb is not laid out the way
// the program reads it: reading a moved field would count nonsense, so it does not attach at all.
func tryDrops() Status {
	var text []byte
	var err error
	for _, root := range tracefsRoots {
		if text, err = os.ReadFile(root + "/events/skb/kfree_skb/format"); err == nil {
			break
		}
	}
	if err != nil {
		return Status{Name: "drops", Status: "detached", Detail: fmt.Sprintf("skb:kfree_skb is not readable: %v", err)}
	}
	if err := checkKfreeSkbFormat(string(text)); err != nil {
		return Status{Name: "drops", Status: "detached", Detail: err.Error()}
	}
	return try("drops", LoadDrops)
}

func dropsColl() *ebpf.Collection {
	for _, l := range pinnedColls {
		if l.Name == "drops" {
			return l.Coll
		}
	}
	return nil
}

// SetDropWatch makes the interfaces the drops program counts equal to ifindexes, which are the VM
// taps. Counts for an interface that is no longer watched are removed, so a reused index never
// inherits another tap's history. It does nothing while the program is not loaded.
func SetDropWatch(ifindexes []uint32) {
	c := dropsColl()
	if c == nil {
		return
	}
	watch, stats := c.Maps["drop_watch"], c.Maps["drop_stats"]
	if watch == nil || stats == nil {
		return
	}
	want := map[uint32]bool{}
	for _, i := range ifindexes {
		want[i] = true
	}
	var have []uint32
	var k uint32
	var v uint8
	for it := watch.Iterate(); it.Next(&k, &v); {
		have = append(have, k)
	}
	for _, i := range have {
		if !want[i] {
			_ = watch.Delete(i)
		}
	}
	one := uint8(1)
	for i := range want {
		_ = watch.Update(i, one, ebpf.UpdateAny)
	}
	var sk DropKey
	var sv []DropVal
	var stale []DropKey
	for it := stats.Iterate(); it.Next(&sk, &sv); {
		if !want[sk.Ifindex] {
			stale = append(stale, sk)
		}
	}
	for _, s := range stale {
		_ = stats.Delete(s)
	}
}

// DropKey and DropVal mirror struct drop_key and struct drop_val in bpf/drops.bpf.c.
type DropKey struct {
	Ifindex uint32
	Reason  uint32
}

type DropVal struct {
	Count    uint64
	Location uint64
}

// DropStats sums the per-CPU counts: what the kernel dropped on each watched tap, by reason.
func DropStats() map[DropKey]DropVal {
	c := dropsColl()
	if c == nil {
		return nil
	}
	m := c.Maps["drop_stats"]
	if m == nil {
		return nil
	}
	out := map[DropKey]DropVal{}
	var k DropKey
	var vals []DropVal
	for it := m.Iterate(); it.Next(&k, &vals); {
		var sum DropVal
		for _, v := range vals {
			sum.Count += v.Count
			if v.Location != 0 {
				sum.Location = v.Location
			}
		}
		out[k] = sum
	}
	return out
}
