package detect

import (
	"net"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/hist"
)

func parseIP(s string) net.IP { return net.ParseIP(s) }

var t0 = time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)

func counters(exits, retrans, delayNs, wakeups uint64) aggregate.Counters {
	return aggregate.Counters{Exits: map[uint32]uint64{1: exits}, Retransmits: retrans, WakeupDelayNs: delayNs, WakeupCount: wakeups}
}

func rule(name, metric, op string, v float64, w time.Duration) Threshold {
	return Threshold{Name: name, Metric: metric, Op: op, Value: v, Window: w, Severity: "medium"}
}

func TestRateOverWindowAndQuietUntilWindowIsFull(t *testing.T) {
	var e Evaluator
	rules := []Threshold{rule("storm", MetricKVMExitsPerSec, ">", 1000, 30*time.Second)}
	vm := func(exits uint64) map[string]aggregate.Counters {
		return map[string]aggregate.Counters{"db": counters(exits, 0, 0, 0)}
	}
	// 100k exits per second, from the first tick.
	var fired []Fired
	for i := 0; i <= 15; i++ { // 0s..30s in 2s ticks
		now := t0.Add(time.Duration(i*2) * time.Second)
		f := e.Evaluate(now, vm(uint64(i*2*100_000)), rules)
		if i < 15 && len(f) != 0 {
			t.Fatalf("fired at %ds, before a full 30s window", i*2)
		}
		fired = f
	}
	if len(fired) != 1 || fired[0].VM != "db" || fired[0].Value < 99_000 || fired[0].Value > 101_000 {
		t.Fatalf("%+v", fired)
	}
	if fired[0].Actual != 30*time.Second {
		t.Fatalf("span %s", fired[0].Actual)
	}
}

func TestBelowThresholdAndOps(t *testing.T) {
	var e Evaluator
	gt := rule("gt", MetricRetransmitsPerSec, ">", 10, 10*time.Second)
	ge := rule("ge", MetricRetransmitsPerSec, ">=", 10, 10*time.Second)
	e.Evaluate(t0, map[string]aggregate.Counters{"db": counters(0, 0, 0, 0)}, []Threshold{gt, ge})
	// Exactly 10 per second over 10s.
	f := e.Evaluate(t0.Add(10*time.Second), map[string]aggregate.Counters{"db": counters(0, 100, 0, 0)}, []Threshold{gt, ge})
	if len(f) != 1 || f[0].Rule.Name != "ge" {
		t.Fatalf("at the line only >= fires: %+v", f)
	}
}

func TestMeanWakeupDelay(t *testing.T) {
	var e Evaluator
	r := []Threshold{rule("slow-wake", MetricWakeupDelayMS, ">", 20, 10*time.Second)}
	e.Evaluate(t0, map[string]aggregate.Counters{"db": counters(0, 0, 5_000_000, 5)}, r)
	// 10 more wakeups totalling 300ms: mean 30ms.
	f := e.Evaluate(t0.Add(10*time.Second), map[string]aggregate.Counters{"db": counters(0, 0, 305_000_000, 15)}, r)
	if len(f) != 1 || f[0].Value < 29.9 || f[0].Value > 30.1 {
		t.Fatalf("%+v", f)
	}
	// No wakeups in the next window: nothing to average, so no alert.
	f = e.Evaluate(t0.Add(20*time.Second), map[string]aggregate.Counters{"db": counters(0, 0, 305_000_000, 15)}, r)
	if len(f) != 0 {
		t.Fatalf("fired with no wakeups: %+v", f)
	}
}

func histWith(ns uint64, n uint64) []uint64 {
	h := make([]uint64, hist.Buckets)
	h[hist.Bucket(ns)] = n
	return h
}

func TestBlockP99UsesOnlyTheWindow(t *testing.T) {
	var e Evaluator
	r := []Threshold{rule("slow-disk", MetricBlockWriteP99MS, ">", 50, 10*time.Second)}
	old := map[string]aggregate.Counters{"db": {BlockWrite: histWith(200_000_000, 1000)}} // ancient slow I/O
	e.Evaluate(t0, old, r)
	// In the window only fast (~1ms) I/O happened. Lifetime p99 is still 200ms.
	cur := histWith(200_000_000, 1000)
	cur[hist.Bucket(1_000_000)] += 500
	f := e.Evaluate(t0.Add(10*time.Second), map[string]aggregate.Counters{"db": {BlockWrite: cur}}, r)
	if len(f) != 0 {
		t.Fatalf("old I/O leaked into the window: %+v", f)
	}
	// Now slow I/O in the window.
	cur[hist.Bucket(200_000_000)] += 50
	f = e.Evaluate(t0.Add(20*time.Second), map[string]aggregate.Counters{"db": {BlockWrite: cur}}, r)
	if len(f) != 1 || f[0].Value < 100 { // bucket edge, up to 2x the true latency
		t.Fatalf("%+v", f)
	}
}

func TestCounterResetAndNewVMAreSkipped(t *testing.T) {
	var e Evaluator
	r := []Threshold{rule("storm", MetricKVMExitsPerSec, ">", 1, 10*time.Second)}
	e.Evaluate(t0, map[string]aggregate.Counters{"db": counters(1_000_000, 0, 0, 0)}, r)
	// db restarted: its counters went backwards. "web" is new mid-window.
	f := e.Evaluate(t0.Add(10*time.Second), map[string]aggregate.Counters{
		"db":  counters(10, 0, 0, 0),
		"web": counters(9_000_000, 0, 0, 0),
	}, r)
	if len(f) != 0 {
		t.Fatalf("guessed at a reset or a VM with no baseline: %+v", f)
	}
}

func TestNoRulesKeepsNoHistoryAndHistoryIsBounded(t *testing.T) {
	var e Evaluator
	cur := map[string]aggregate.Counters{"db": counters(1, 0, 0, 0)}
	e.Evaluate(t0, cur, nil)
	if len(e.history) != 0 {
		t.Fatal("kept history with no rules")
	}
	r := []Threshold{rule("x", MetricKVMExitsPerSec, ">", 1e12, 10*time.Second)}
	for i := 0; i < 1000; i++ {
		e.Evaluate(t0.Add(time.Duration(i)*2*time.Second), cur, r)
	}
	if len(e.history) > 10 { // 10s window at 2s ticks, plus the baseline edge
		t.Fatalf("history grew to %d snapshots", len(e.history))
	}
}

func TestSuppressor(t *testing.T) {
	var s Suppressor
	w := time.Minute
	if ok, _ := s.Allow("k", t0, w); !ok {
		t.Fatal("first was suppressed")
	}
	for i := 1; i <= 3; i++ {
		if ok, _ := s.Allow("k", t0.Add(time.Duration(i)*time.Second), w); ok {
			t.Fatalf("repeat %d let through", i)
		}
	}
	if ok, _ := s.Allow("other", t0.Add(time.Second), w); !ok {
		t.Fatal("a different key was suppressed")
	}
	ok, held := s.Allow("k", t0.Add(w), w)
	if !ok || held != 3 {
		t.Fatalf("after the window: ok=%v held=%d", ok, held)
	}
	if ok, _ := s.Allow("k", t0.Add(w+time.Second), w); ok {
		t.Fatal("window did not restart")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := s.Allow("k", t0, 0); !ok {
			t.Fatal("zero window must never suppress")
		}
	}
}

func TestSuppressorTableIsBounded(t *testing.T) {
	var s Suppressor
	for i := 0; i < maxSuppressKeys+500; i++ {
		s.Allow(string(rune('a'+i%26))+"-"+time.Duration(i).String(), t0, time.Hour)
	}
	if len(s.seen) > maxSuppressKeys {
		t.Fatalf("table grew to %d", len(s.seen))
	}
	// Full of live keys: a new one still alerts, and is not recorded.
	if ok, _ := s.Allow("brand-new", t0, time.Hour); !ok {
		t.Fatal("dropped an alert because the table was full")
	}
	// Once the old ones expire there is room again.
	if ok, _ := s.Allow("brand-new", t0.Add(2*time.Hour), time.Hour); !ok || len(s.seen) > maxSuppressKeys {
		t.Fatalf("len %d", len(s.seen))
	}
}

func TestNewMetricsUseOnlyTheWindow(t *testing.T) {
	var e Evaluator
	rules := []Threshold{
		rule("slow-exit", MetricKVMExitP99MS, ">", 1, 10*time.Second),
		rule("cpu-wait", MetricRunqueueP99MS, ">", 1, 10*time.Second),
		rule("write-rate", MetricBlockWriteBPS, ">", 1_000_000, 10*time.Second),
		rule("iops", MetricBlockIOPS, ">=", 500, 10*time.Second),
	}
	base := aggregate.Counters{KVMLat: histWith(50_000_000, 900), SchedHist: histWith(50_000_000, 900), BlockWriteBytes: 100, BlockWriteOps: 10}
	e.Evaluate(t0, map[string]aggregate.Counters{"db": base}, rules)
	// Ancient slow samples are still in the lifetime histograms. In the window only
	// fast ones were added, plus 20 MB written over 10 s in 6000 requests.
	cur := aggregate.Counters{
		KVMLat: histWith(50_000_000, 900), SchedHist: histWith(50_000_000, 900),
		BlockWriteBytes: 100 + 20_000_000, BlockWriteOps: 10 + 6000, BlockReadOps: 0,
	}
	cur.KVMLat[hist.Bucket(10_000)] += 100
	cur.SchedHist[hist.Bucket(10_000)] += 100
	f := e.Evaluate(t0.Add(10*time.Second), map[string]aggregate.Counters{"db": cur}, rules)
	got := map[string]float64{}
	for _, x := range f {
		got[x.Rule.Name] = x.Value
	}
	if _, ok := got["slow-exit"]; ok {
		t.Fatalf("old exits leaked into the window: %+v", f)
	}
	if _, ok := got["cpu-wait"]; ok {
		t.Fatalf("old run-queue delay leaked into the window: %+v", f)
	}
	if got["write-rate"] < 1_999_000 || got["write-rate"] > 2_001_000 {
		t.Fatalf("write rate %v: %+v", got["write-rate"], f)
	}
	if got["iops"] != 600 {
		t.Fatalf("iops %v", got["iops"])
	}
	// Slow ones in the window do fire.
	cur.KVMLat[hist.Bucket(30_000_000)] += 10
	cur.SchedHist[hist.Bucket(30_000_000)] += 10
	f = e.Evaluate(t0.Add(20*time.Second), map[string]aggregate.Counters{"db": cur}, rules[:2])
	if len(f) != 2 {
		t.Fatalf("%+v", f)
	}
}

func TestGuestDropsPerSecReadsOnlyWhatShukraDidNotDrop(t *testing.T) {
	var e Evaluator
	r := []Threshold{{Name: "guest-drops", Metric: MetricGuestDropsPerSec, Op: ">", Value: 5, Window: 10 * time.Second, Severity: "high"}}
	vms := map[string]aggregate.Counters{"db": {}}
	e.SetTapTotals(map[string]aggregate.TapTotals{"db": {ForeignDrops: 100, DropsOK: true}})
	e.Evaluate(t0, vms, r)
	e.SetTapTotals(map[string]aggregate.TapTotals{"db": {ForeignDrops: 200, DropsOK: true}}) // 100 more in 10 s: 10 a second
	f := e.Evaluate(t0.Add(10*time.Second), vms, r)
	if len(f) != 1 || f[0].VM != "db" || f[0].Value != 10 {
		t.Fatalf("%+v", f)
	}
	e.SetTapTotals(map[string]aggregate.TapTotals{"db": {ForeignDrops: 210, DropsOK: true}}) // 1 a second: under the threshold
	if f = e.Evaluate(t0.Add(20*time.Second), vms, r); len(f) != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestGuestDropsSaysNothingWhileTheDropsProgramIsNotMeasuring(t *testing.T) {
	var e Evaluator
	r := []Threshold{{Name: "guest-drops", Metric: MetricGuestDropsPerSec, Op: ">=", Value: 0, Window: 10 * time.Second, Severity: "high"}}
	vms := map[string]aggregate.Counters{"db": {}}
	// Not measuring at either end: not zero, nothing.
	e.Evaluate(t0, vms, r)
	if f := e.Evaluate(t0.Add(10*time.Second), vms, r); len(f) != 0 {
		t.Fatalf("a rule fired with no measurement: %+v", f)
	}
	// Measuring only now: the base was not measured, so there is no window to compare.
	e.SetTapTotals(map[string]aggregate.TapTotals{"db": {ForeignDrops: 500, DropsOK: true}})
	if f := e.Evaluate(t0.Add(20*time.Second), vms, r); len(f) != 0 {
		t.Fatalf("compared a measurement with a non-measurement: %+v", f)
	}
}

func TestTheGuestDropsMetricIsAcceptedInARuleFile(t *testing.T) {
	c, err := Parse([]byte("thresholds:\n  - {name: d, metric: guest_drops_per_sec, value: 5}\n"))
	if err != nil || len(c.Thresholds) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestTheConnectionOutcomeMetricsEachReadTheirOwnCounter(t *testing.T) {
	for _, c := range []struct {
		metric string
		totals func(n uint64) aggregate.TapTotals
	}{
		{MetricConnectRefusedPerSec, func(n uint64) aggregate.TapTotals {
			return aggregate.TapTotals{OutRefused: n, OutTimeout: 1000, InSyn: 1000, OutcomesOK: true} // the others must not count
		}},
		{MetricConnectTimeoutsPerSec, func(n uint64) aggregate.TapTotals {
			return aggregate.TapTotals{OutTimeout: n, OutRefused: 1000, InSyn: 1000, OutcomesOK: true}
		}},
		{MetricInboundPerSec, func(n uint64) aggregate.TapTotals {
			return aggregate.TapTotals{InSyn: n, OutRefused: 1000, OutTimeout: 1000, OutcomesOK: true}
		}},
	} {
		var e Evaluator
		r := []Threshold{{Name: "r", Metric: c.metric, Op: ">", Value: 5, Window: 10 * time.Second, Severity: "medium"}}
		vms := map[string]aggregate.Counters{"db": {}}
		e.SetTapTotals(map[string]aggregate.TapTotals{"db": c.totals(100)})
		e.Evaluate(t0, vms, r)
		e.SetTapTotals(map[string]aggregate.TapTotals{"db": c.totals(200)}) // 100 more in 10 s
		f := e.Evaluate(t0.Add(10*time.Second), vms, r)
		if len(f) != 1 || f[0].Value != 10 {
			t.Errorf("%s: %+v", c.metric, f)
		}
	}
}

func TestTheConnectionMetricsSayNothingWhileTheTapProgramIsNotMeasuring(t *testing.T) {
	for _, metric := range []string{MetricConnectRefusedPerSec, MetricConnectTimeoutsPerSec, MetricInboundPerSec} {
		var e Evaluator
		r := []Threshold{{Name: "r", Metric: metric, Op: ">=", Value: 0, Window: 10 * time.Second, Severity: "medium"}}
		vms := map[string]aggregate.Counters{"db": {}}
		// Not measuring at either end.
		e.SetTapTotals(map[string]aggregate.TapTotals{"db": {OutRefused: 5, OutTimeout: 5, InSyn: 5}})
		e.Evaluate(t0, vms, r)
		e.SetTapTotals(map[string]aggregate.TapTotals{"db": {OutRefused: 500, OutTimeout: 500, InSyn: 500}})
		if f := e.Evaluate(t0.Add(10*time.Second), vms, r); len(f) != 0 {
			t.Errorf("%s fired with no measurement: %+v", metric, f)
		}
		// Measuring only now: the base was not, so there is no window to compare.
		e.SetTapTotals(map[string]aggregate.TapTotals{"db": {OutRefused: 900, OutTimeout: 900, InSyn: 900, OutcomesOK: true}})
		if f := e.Evaluate(t0.Add(20*time.Second), vms, r); len(f) != 0 {
			t.Errorf("%s compared a measurement with a non-measurement: %+v", metric, f)
		}
	}
}

func TestVCPUPreemptedMSPerSecSumsTheWindowsPreemptionAndSaysNothingWithoutTheSchedProgram(t *testing.T) {
	var e Evaluator
	r := []Threshold{{Name: "stolen", Metric: MetricVCPUPreemptedMSPerSec, Op: ">", Value: 100, Window: 10 * time.Second, Severity: "high"}}
	on := func(ns uint64) map[string]aggregate.Counters {
		return map[string]aggregate.Counters{"db": {OnCPUNs: 1, PreemptNs: ns}}
	}
	e.Evaluate(t0, on(1_000_000_000), r)
	// 3 s of preemption in 10 s across the vCPUs: 300 ms a second.
	f := e.Evaluate(t0.Add(10*time.Second), on(4_000_000_000), r)
	if len(f) != 1 || f[0].VM != "db" || f[0].Value != 300 {
		t.Fatalf("%+v", f)
	}
	// 0.5 s in the next 10 s is 50 ms a second: the old preemption is not counted again.
	if f = e.Evaluate(t0.Add(20*time.Second), on(4_500_000_000), r); len(f) != 0 {
		t.Fatalf("%+v", f)
	}
	// A counter that went backwards (the thread restarted) is skipped, not a giant number.
	if f = e.Evaluate(t0.Add(30*time.Second), on(10), r); len(f) != 0 {
		t.Fatalf("%+v", f)
	}

	// The sched program was not measuring this VM: nothing, not zero, even for a rule that a zero would satisfy.
	var q Evaluator
	z := []Threshold{{Name: "z", Metric: MetricVCPUPreemptedMSPerSec, Op: ">=", Value: 0, Window: 10 * time.Second, Severity: "high"}}
	off := map[string]aggregate.Counters{"db": {}}
	q.Evaluate(t0, off, z)
	if f = q.Evaluate(t0.Add(10*time.Second), off, z); len(f) != 0 {
		t.Fatalf("a rule fired with no measurement: %+v", f)
	}
}

func TestTheVCPUPreemptedMetricIsAcceptedInARuleFile(t *testing.T) {
	c, err := Parse([]byte("thresholds:\n  - {name: p, metric: vcpu_preempted_ms_per_sec, value: 200}\n"))
	if err != nil || len(c.Thresholds) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
}
