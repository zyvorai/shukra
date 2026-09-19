package detect

import (
	"fmt"
	"sort"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/hist"
)

// Fired is one threshold that was crossed for one VM.
type Fired struct {
	Rule   Threshold
	VM     string
	Value  float64
	Actual time.Duration // the span the value was computed over
}

// Message is the human line for the detection.
func (f Fired) Message() string {
	return fmt.Sprintf("%s: %s %.4g %s %.4g over %s", f.Rule.Name, f.Rule.Metric, f.Value, f.Rule.Op, f.Rule.Value, f.Actual.Round(time.Second))
}

// vmSnap is the slice of a VM's cumulative counters that rules read.
type vmSnap struct {
	exits, delayNs, wakeups, retrans uint64
	readBytes, writeBytes, ops       uint64
	read, write, kvmLat, schedHist   []uint64
}

type snapshot struct {
	at  time.Time
	vms map[string]vmSnap
}

// Evaluator compares each VM's cumulative counters against a snapshot one
// window ago. It never reads a partial window: a rule stays quiet until enough
// history exists, and a VM that appeared mid-window is skipped. The counters
// are the QEMU process's, not the guest's. Not safe for concurrent use.
type Evaluator struct {
	history []snapshot
}

// Evaluate records cur and returns the rules that are crossed right now.
// With no rules it keeps no history at all.
func (e *Evaluator) Evaluate(now time.Time, cur map[string]aggregate.Counters, rules []Threshold) []Fired {
	if len(rules) == 0 {
		e.history = nil
		return nil
	}
	var keep time.Duration
	for _, r := range rules {
		keep = max(keep, r.Window)
	}
	e.record(now, cur, keep)

	names := make([]string, 0, len(cur))
	for n := range cur {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []Fired
	for _, r := range rules {
		base, ok := e.base(now, r.Window)
		if !ok {
			continue
		}
		span := now.Sub(base.at)
		for _, vm := range names {
			old, ok := base.vms[vm]
			if !ok {
				continue
			}
			v, ok := metric(r.Metric, old, snap(cur[vm]), span)
			if !ok {
				continue
			}
			if (r.Op == ">" && v > r.Value) || (r.Op == ">=" && v >= r.Value) {
				out = append(out, Fired{Rule: r, VM: vm, Value: v, Actual: span})
			}
		}
	}
	return out
}

func (e *Evaluator) record(now time.Time, cur map[string]aggregate.Counters, keep time.Duration) {
	s := snapshot{at: now, vms: make(map[string]vmSnap, len(cur))}
	for n, c := range cur {
		s.vms[n] = snap(c)
	}
	e.history = append(e.history, s)
	// Keep one snapshot at or before the oldest edge any rule needs.
	cut := now.Add(-keep)
	i := 0
	for i+1 < len(e.history) && !e.history[i+1].at.After(cut) {
		i++
	}
	e.history = e.history[i:]
}

// base is the newest snapshot at least window old.
func (e *Evaluator) base(now time.Time, window time.Duration) (snapshot, bool) {
	cut := now.Add(-window)
	for i := len(e.history) - 1; i >= 0; i-- {
		if !e.history[i].at.After(cut) {
			return e.history[i], true
		}
	}
	return snapshot{}, false
}

func snap(c aggregate.Counters) vmSnap {
	return vmSnap{
		exits: c.TotalExits(), delayNs: c.WakeupDelayNs, wakeups: c.WakeupCount, retrans: c.Retransmits,
		readBytes: c.BlockReadBytes, writeBytes: c.BlockWriteBytes, ops: c.BlockReadOps + c.BlockWriteOps,
		read: append([]uint64(nil), c.BlockRead...), write: append([]uint64(nil), c.BlockWrite...),
		kvmLat: append([]uint64(nil), c.KVMLat...), schedHist: append([]uint64(nil), c.SchedHist...),
	}
}

// metric returns false when there is nothing to say: no I/O in the window, or a
// counter went backwards (a thread exited or a map entry was evicted). A reset
// is skipped rather than guessed at.
func metric(name string, old, cur vmSnap, span time.Duration) (float64, bool) {
	secs := span.Seconds()
	switch name {
	case MetricKVMExitsPerSec:
		d, ok := sub(cur.exits, old.exits)
		return float64(d) / secs, ok
	case MetricRetransmitsPerSec:
		d, ok := sub(cur.retrans, old.retrans)
		return float64(d) / secs, ok
	case MetricWakeupDelayMS:
		dn, ok1 := sub(cur.delayNs, old.delayNs)
		dc, ok2 := sub(cur.wakeups, old.wakeups)
		if !ok1 || !ok2 || dc == 0 {
			return 0, false
		}
		return float64(dn) / float64(dc) / 1e6, true
	case MetricBlockReadP99MS:
		return p99ms(old.read, cur.read)
	case MetricBlockWriteP99MS:
		return p99ms(old.write, cur.write)
	case MetricKVMExitP99MS:
		return p99ms(old.kvmLat, cur.kvmLat)
	case MetricRunqueueP99MS:
		return p99ms(old.schedHist, cur.schedHist)
	case MetricBlockReadBPS:
		d, ok := sub(cur.readBytes, old.readBytes)
		return float64(d) / secs, ok
	case MetricBlockWriteBPS:
		d, ok := sub(cur.writeBytes, old.writeBytes)
		return float64(d) / secs, ok
	case MetricBlockIOPS:
		d, ok := sub(cur.ops, old.ops)
		return float64(d) / secs, ok
	}
	return 0, false
}

func sub(cur, old uint64) (uint64, bool) {
	if cur < old {
		return 0, false
	}
	return cur - old, true
}

// p99ms is the 99th percentile of the requests that finished in the window. The
// histogram is log2, so this is a bucket edge and can read up to 2x high.
func p99ms(old, cur []uint64) (float64, bool) {
	if len(cur) == 0 {
		return 0, false
	}
	d := make([]uint64, len(cur))
	var total uint64
	for i := range cur {
		var o uint64
		if i < len(old) {
			o = old[i]
		}
		if cur[i] < o {
			return 0, false
		}
		d[i] = cur[i] - o
		total += d[i]
	}
	if total == 0 {
		return 0, false
	}
	return float64(hist.Percentile(d, 99)) / 1e6, true
}
