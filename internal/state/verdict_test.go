package state

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/identity"
)

func causes(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Cause+":"+f.Confidence)
	}
	return out
}

func find(fs []Finding, cause string) *Finding {
	for i := range fs {
		if fs[i].Cause == cause {
			return &fs[i]
		}
	}
	return nil
}

var (
	ms    = uint64(1_000_000)
	quiet = []aggregate.KVMRow{{Measured: true, LatencyP99Ns: 4096}}
)

func TestNothingToSayWhenNothingIsMeasured(t *testing.T) {
	if got := causes(diagnose(false, nil, nil, nil, nil, nil, nil, nil)); len(got) != 1 || got[0] != "unknown_vm:high" {
		t.Fatalf("%v", got)
	}
	got := diagnose(true, []aggregate.KVMRow{{}}, []aggregate.SchedRow{{}}, nil, []aggregate.BlockRow{{}}, nil, nil, nil)
	if len(got) != 1 || got[0].Cause != "not_measured" || !strings.Contains(got[0].Summary, "programs") {
		t.Fatalf("%+v", got)
	}
}

func TestHostCPUContentionNeedsAVCPUThreadToBeHigh(t *testing.T) {
	sched := []aggregate.SchedRow{{Measured: true, WakeupDelayP99Ns: 30 * ms}}
	threads := []aggregate.ThreadRow{
		{TID: 11, Comm: "CPU 0/KVM", Role: "vcpu", WakeupDelayP99Ns: 30 * ms},
		{TID: 12, Comm: "IO iothread1", Role: "iothread", WakeupDelayP99Ns: 900 * ms}, // worse, but not a vCPU
	}
	f := find(diagnose(true, quiet, sched, threads, nil, nil, nil, nil), "host_cpu_contention")
	if f == nil || f.Confidence != "high" || !strings.Contains(f.Evidence[0], "vCPU thread 11") || !strings.Contains(f.Evidence[0], "30") {
		t.Fatalf("%+v", f)
	}
	// With no vCPU thread to point at, do not claim more than medium.
	f = find(diagnose(true, quiet, sched, nil, nil, nil, nil, nil), "host_cpu_contention")
	if f == nil || f.Confidence != "medium" || !strings.Contains(f.Evidence[0], "the VM's threads") {
		t.Fatalf("%+v", f)
	}
	// A vCPU waiting 2.1 ms is medium, and 300 µs is not a finding.
	mid := []aggregate.ThreadRow{{TID: 11, Role: "vcpu", WakeupDelayP99Ns: 2_100_000}}
	if f = find(diagnose(true, quiet, sched, mid, nil, nil, nil, nil), "host_cpu_contention"); f == nil || f.Confidence != "medium" {
		t.Fatalf("%+v", f)
	}
	low := []aggregate.ThreadRow{{TID: 11, Role: "vcpu", WakeupDelayP99Ns: 300_000}}
	if f = find(diagnose(true, quiet, []aggregate.SchedRow{{Measured: true}}, low, nil, nil, nil, nil), "host_cpu_contention"); f != nil {
		t.Fatalf("300 µs is not contention: %+v", f)
	}
}

func TestStorageLatencyThresholds(t *testing.T) {
	blk := func(read, write uint64) []aggregate.BlockRow {
		return []aggregate.BlockRow{{Measured: true, ReadP99Ns: read, WriteP99Ns: write, ReadMaxNs: 2 * read, WriteMaxNs: 2 * write, ReadOps: 5, WriteOps: 7}}
	}
	for _, c := range []struct {
		read, write uint64
		want        string
	}{{5 * ms, 5 * ms, ""}, {11 * ms, 1 * ms, "medium"}, {1 * ms, 60 * ms, "high"}} {
		f := find(diagnose(true, quiet, nil, nil, blk(c.read, c.write), nil, nil, nil), "storage_latency")
		if c.want == "" {
			if f != nil {
				t.Fatalf("%+v under threshold produced %+v", c, f)
			}
			continue
		}
		if f == nil || f.Confidence != c.want || !strings.Contains(f.Evidence[0], "12 requests") {
			t.Fatalf("%+v: %+v", c, f)
		}
	}
	// It names the direction that is slow.
	if f := find(diagnose(true, quiet, nil, nil, blk(1*ms, 60*ms), nil, nil, nil), "storage_latency"); !strings.Contains(f.Evidence[0], "write") {
		t.Fatalf("%v", f.Evidence)
	}
}

func TestKVMExitHandlingSkipsHaltsWhenNamingTheCostliestExit(t *testing.T) {
	k := []aggregate.KVMRow{{
		Measured: true, LatencyP99Ns: 20 * ms,
		TopByTime: []aggregate.Reason{
			{Reason: 12, Name: "hlt", Count: 9, TotalNs: 90_000 * ms}, // guest idle
			{Reason: 30, Name: "io_instruction", Count: 500, TotalNs: 4_000 * ms},
		},
	}}
	f := find(diagnose(true, k, nil, nil, nil, nil, nil, nil), "kvm_exit_handling")
	if f == nil || f.Confidence != "high" || len(f.Evidence) != 2 ||
		!strings.Contains(f.Evidence[1], "io_instruction") || strings.Contains(f.Evidence[1], "hlt") {
		t.Fatalf("%+v", f)
	}
	// An unnamed reason (AMD, arm64) is still reported, by number.
	k[0].TopByTime = []aggregate.Reason{{Reason: 123, Count: 4, TotalNs: 10 * ms}}
	if f = find(diagnose(true, k, nil, nil, nil, nil, nil, nil), "kvm_exit_handling"); !strings.Contains(f.Evidence[1], "reason 123") {
		t.Fatalf("%+v", f)
	}
	k[0].LatencyP99Ns = 2 * ms
	if f = find(diagnose(true, k, nil, nil, nil, nil, nil, nil), "kvm_exit_handling"); f == nil || f.Confidence != "medium" {
		t.Fatalf("%+v", f)
	}
	k[0].LatencyP99Ns = 200_000
	if find(diagnose(true, k, nil, nil, nil, nil, nil, nil), "kvm_exit_handling") != nil {
		t.Fatal("200 µs is not slow")
	}
}

func TestRetransmitsAreLowConfidenceAndSaySoAboutWhoseTraffic(t *testing.T) {
	net := []aggregate.NetRow{{Retransmits: 50}}
	f := find(diagnose(true, quiet, nil, nil, nil, net, nil, nil), "tcp_retransmits")
	if f == nil || f.Confidence != "low" || !strings.Contains(f.Summary, "not the guest") {
		t.Fatalf("%+v", f)
	}
	if find(diagnose(true, quiet, nil, nil, nil, []aggregate.NetRow{{Retransmits: 3}}, nil, nil), "tcp_retransmits") != nil {
		t.Fatal("3 retransmits is noise")
	}
}

func TestQuietHostSaysThePauseMayBeInsideTheGuest(t *testing.T) {
	got := diagnose(true, quiet, []aggregate.SchedRow{{Measured: true, WakeupDelayP99Ns: 4096}}, nil,
		[]aggregate.BlockRow{{Measured: true, ReadP99Ns: 1 * ms}}, nil, nil, nil)
	if len(got) != 1 || got[0].Cause != "no_host_cause" || got[0].Confidence != "low" || !strings.Contains(got[0].Summary, "inside it") {
		t.Fatalf("%+v", got)
	}
}

func TestFindingsAreRankedBySupport(t *testing.T) {
	sched := []aggregate.SchedRow{{Measured: true}}
	threads := []aggregate.ThreadRow{{TID: 1, Role: "vcpu", WakeupDelayP99Ns: 2_100_000}} // medium
	block := []aggregate.BlockRow{{Measured: true, WriteP99Ns: 60 * ms}}                  // high
	net := []aggregate.NetRow{{Retransmits: 99}}                                          // low
	got := causes(diagnose(true, quiet, sched, threads, block, net, nil, nil))
	want := []string{"storage_latency:high", "host_cpu_contention:medium", "tcp_retransmits:low"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestExplainCarriesFindingsAndTheirBasis(t *testing.T) {
	st := New("node-07")
	st.SetVMs([]identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}, ThreadInfo: []identity.Thread{
		{TID: 100, Comm: "qemu-system-x86", Role: "main"}, {TID: 101, Comm: "CPU 0/KVM", Role: "vcpu"},
	}}})
	h := make([]uint64, 64)
	h[24] = 50 // a run-queue delay of up to 33 ms
	st.SetCounters(map[uint32]aggregate.Counters{101: {OnCPUNs: 1, WakeupCount: 50, SchedHist: h}})
	ex := st.Explain("db", timeNow())
	if len(ex.Findings) == 0 || ex.Findings[0].Cause != "host_cpu_contention" || ex.Findings[0].Confidence != "high" {
		t.Fatalf("%+v", ex.Findings)
	}
	if !strings.Contains(ex.Basis, "2x") || len(ex.Missing) == 0 {
		t.Fatalf("basis %q missing %v", ex.Basis, ex.Missing)
	}
	// A VM that does not exist gets one clear finding, not a guess.
	if ex = st.Explain("nope", timeNow()); len(ex.Findings) != 1 || ex.Findings[0].Cause != "unknown_vm" {
		t.Fatalf("%+v", ex.Findings)
	}
}

func timeNow() time.Time { return time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC) }

func TestTrafficDroppedByAnotherProgramIsACauseNotNoHostCause(t *testing.T) {
	quiet := []aggregate.KVMRow{{Measured: true}}
	other := []DropTap{{VM: "db", Tap: "tap0", KernelDrops: 60, ShukraDropped: 2, OtherDrops: 58, Reasons: []DropReason{{Reason: "TC_INGRESS", Count: 60}}}}
	got := diagnose(true, quiet, nil, nil, nil, nil, other, nil)
	f := find(got, "guest_traffic_dropped")
	if f == nil || f.Confidence != "medium" || !strings.Contains(f.Evidence[0], "58 packets") || !strings.Contains(f.Evidence[0], "Shukra dropped 2") ||
		!strings.Contains(f.Evidence[0], "Mostly TC_INGRESS") || !strings.Contains(f.Summary, "bpftool net show dev tap0") {
		t.Fatalf("%+v", got)
	}
	if find(got, "no_host_cause") != nil {
		t.Fatal("a real cause was reported alongside 'no host cause'")
	}
}

func TestDropsThatAreShukrasOwnOrTooFewAreNotAFinding(t *testing.T) {
	quiet := []aggregate.KVMRow{{Measured: true}}
	// All of it is isolation: the kernel counted what Shukra dropped, so nothing is left over.
	own := []DropTap{{VM: "db", Tap: "tap0", KernelDrops: 500, ShukraDropped: 500, OtherDrops: 0}}
	// A few packets of skew between the two reads is not another program.
	skew := []DropTap{{VM: "db", Tap: "tap0", KernelDrops: 503, ShukraDropped: 500, OtherDrops: 3}}
	for name, d := range map[string][]DropTap{"own": own, "skew": skew} {
		got := diagnose(true, quiet, nil, nil, nil, nil, d, nil)
		if find(got, "guest_traffic_dropped") != nil || len(got) != 1 || got[0].Cause != "no_host_cause" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}

func TestAFullTapQueueSaysTheGuestIsNotReadingItsNIC(t *testing.T) {
	quiet := []aggregate.KVMRow{{Measured: true}}
	full := []DropTap{{VM: "db", Tap: "tap0", KernelDrops: 90, OtherDrops: 90, QueueFull: 90, Reasons: []DropReason{{Reason: "FULL_RING", Count: 90}}}}
	f := find(diagnose(true, quiet, nil, nil, nil, nil, full, nil), "guest_not_reading_nic")
	if f == nil || !strings.Contains(f.Evidence[0], "90 packets") || !strings.Contains(f.Evidence[0], "tap0") || !strings.Contains(f.Summary, "not taking them") {
		t.Fatalf("%+v", f)
	}
}
