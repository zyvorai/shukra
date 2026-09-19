package aggregate

import (
	"testing"

	"github.com/zyvorai/shukra/internal/identity"
)

func TestJoinAndHostRollup(t *testing.T) {
	vms := []identity.VM{{
		Name: "payment-prod-03", Runtime: "qemu", PID: 100, Threads: []int{100, 101},
	}}
	by := map[uint32]Counters{
		101: {Exits: map[uint32]uint64{1: 10, 2: 3}, Entries: 10, Connects: 4, Retransmits: 1},
		999: {Connects: 7},
	}
	kvm := KVM(vms, by, "payment-prod-03")
	if len(kvm) != 1 || kvm[0].Exits != 13 || kvm[0].Top[0].Reason != 1 {
		t.Fatalf("%+v", kvm)
	}
	net := Net(vms, by, "")
	var host, vm NetRow
	for _, row := range net {
		if row.VM == Host {
			host = row
		}
		if row.VM == "payment-prod-03" {
			vm = row
		}
	}
	if vm.Connects != 4 || vm.GuestAttributed || vm.Attribution != "qemu-process" {
		t.Fatalf("vm %+v", vm)
	}
	if host.Connects != 7 || host.Attribution == "qemu-process" {
		t.Fatalf("host %+v", host)
	}
}

func TestBlockPercentiles(t *testing.T) {
	read := make([]uint64, 64)
	read[10] = 10
	vms := []identity.VM{{Name: "db", PID: 1, Threads: []int{1}}}
	rows := Block(vms, map[uint32]Counters{1: {BlockIssues: 10, BlockRead: read, BlockReadMax: 1500}}, "db")
	if len(rows) != 1 || rows[0].ReadP50Ns == 0 || rows[0].ReadP99Ns == 0 || !rows[0].Measured {
		t.Fatalf("%+v", rows)
	}
}

func hist64(bucket int, n uint64) []uint64 {
	h := make([]uint64, 64)
	h[bucket] = n
	return h
}

func TestSchedRunQueuePercentilesMergeThreads(t *testing.T) {
	vms := []identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}}}
	by := map[uint32]Counters{
		100: {OnCPUNs: 5, WakeupCount: 99, SchedHist: hist64(10, 99)}, // ~2µs
		101: {OnCPUNs: 7, WakeupCount: 1, SchedHist: hist64(20, 1)},   // ~2ms, one outlier
	}
	rows := Sched(vms, by, "db")
	if len(rows) != 1 || !rows[0].Measured || rows[0].OnCPUNs != 12 {
		t.Fatalf("%+v", rows)
	}
	// 100 samples, one slow: the 99th is still a fast one, so p50 and p99 both read
	// the fast bucket's edge. Only the maximum would show the outlier.
	if rows[0].WakeupDelayP50Ns != 1<<11 || rows[0].WakeupDelayP99Ns != 1<<11 {
		t.Fatalf("p50=%d p99=%d", rows[0].WakeupDelayP50Ns, rows[0].WakeupDelayP99Ns)
	}
	if len(rows[0].WakeupHist) != 64 || rows[0].WakeupHist[10] != 99 || rows[0].WakeupHist[20] != 1 {
		t.Fatalf("merged histogram: %v", rows[0].WakeupHist)
	}
}

func TestSchedThreadsSeparatesVCPUFromIOThread(t *testing.T) {
	vms := []identity.VM{
		{Name: "db", PID: 100, Threads: []int{100, 101, 102}, ThreadInfo: []identity.Thread{
			{TID: 100, Comm: "qemu-system-x86", Role: "main"},
			{TID: 101, Comm: "CPU 0/KVM", Role: "vcpu"},
			{TID: 102, Comm: "IO iothread1", Role: "iothread"}, // no counters yet
		}},
		{Name: "web", PID: 200, Threads: []int{200}},
	}
	by := map[uint32]Counters{
		101: {OnCPUNs: 900, WakeupCount: 10, WakeupDelayNs: 50, SchedHist: hist64(12, 10)},
		100: {OnCPUNs: 100},
		200: {OnCPUNs: 1}, // a VM whose thread info was not read
		999: {OnCPUNs: 1 << 40},
	}
	got := SchedThreads(vms, by, "db")
	if len(got) != 2 {
		t.Fatalf("a thread with no counters must be left out, and other VMs excluded: %+v", got)
	}
	var vcpu ThreadRow
	for _, r := range got {
		if r.Role == "vcpu" {
			vcpu = r
		}
	}
	if vcpu.TID != 101 || vcpu.Comm != "CPU 0/KVM" || vcpu.OnCPUNs != 900 || vcpu.WakeupDelayP99Ns != 1<<13 {
		t.Fatalf("%+v", vcpu)
	}
	all := SchedThreads(vms, by, "")
	if len(all) != 3 { // db: 100 and 101; web: 200 with an "unknown" role
		t.Fatalf("%+v", all)
	}
	for _, r := range all {
		if r.VM == "web" && r.Role != "unknown" {
			t.Fatalf("role %q", r.Role)
		}
		if r.TID == 999 {
			t.Fatal("host thread attributed to a VM")
		}
	}
}

func TestBlockOpsBytesMaxMergeAcrossThreads(t *testing.T) {
	vms := []identity.VM{{Name: "db", PID: 1, Threads: []int{1, 2}}}
	by := map[uint32]Counters{
		1: {BlockIssues: 3, BlockReadOps: 2, BlockReadBytes: 8192, BlockReadMax: 1_500_000, BlockRead: hist64(20, 2),
			BlockWriteOps: 1, BlockWriteBytes: 4096, BlockWriteMax: 900_000, BlockWrite: hist64(19, 1)},
		2: {BlockIssues: 1, BlockReadOps: 1, BlockReadBytes: 512, BlockReadMax: 3_000_000, BlockRead: hist64(21, 1)},
	}
	rows := Block(vms, by, "db")
	if len(rows) != 1 {
		t.Fatalf("%+v", rows)
	}
	r := rows[0]
	if r.ReadOps != 3 || r.ReadBytes != 8704 || r.WriteOps != 1 || r.WriteBytes != 4096 {
		t.Fatalf("sums: %+v", r)
	}
	// The maximum is the largest across threads, never a sum.
	if r.ReadMaxNs != 3_000_000 || r.WriteMaxNs != 900_000 {
		t.Fatalf("max: read %d write %d", r.ReadMaxNs, r.WriteMaxNs)
	}
	if len(r.ReadHist) != 64 || r.ReadHist[20] != 2 || r.ReadHist[21] != 1 || r.WriteHist[19] != 1 {
		t.Fatalf("hist: %v %v", r.ReadHist, r.WriteHist)
	}
	if !r.Measured || r.Issues != 4 {
		t.Fatalf("%+v", r)
	}
}

func TestKVMTopByTimeIsNotTopByCount(t *testing.T) {
	vms := []identity.VM{{Name: "db", PID: 100, Threads: []int{100, 101}}}
	by := map[uint32]Counters{
		100: {
			Exits:   map[uint32]uint64{10: 1_000_000, 48: 40, 12: 5},
			ExitNs:  map[uint32]uint64{10: 2_000_000_000, 48: 8_000_000_000, 12: 90_000_000_000},
			Entries: 1,
		},
		101: {
			Exits:  map[uint32]uint64{10: 1_000_000},
			ExitNs: map[uint32]uint64{10: 2_000_000_000},
			KVMLat: hist64(15, 99),
		},
	}
	rows := KVM(vms, by, "db")
	if len(rows) != 1 {
		t.Fatalf("%+v", rows)
	}
	r := rows[0]
	// Most frequent: reason 10, summed across threads. Costliest: 12 (a halt, so
	// that time is guest idle), then 48.
	if r.Top[0].Reason != 10 || r.Top[0].Count != 2_000_000 || r.Top[0].TotalNs != 4_000_000_000 {
		t.Fatalf("top by count: %+v", r.Top)
	}
	if r.TopByTime[0].Reason != 12 || r.TopByTime[1].Reason != 48 || r.TopByTime[0].TotalNs != 90_000_000_000 {
		t.Fatalf("top by time: %+v", r.TopByTime)
	}
	if r.LatencyP50Ns != 1<<16 || r.LatencyP99Ns != 1<<16 || len(r.LatencyHist) != 64 {
		t.Fatalf("latency %d %d", r.LatencyP50Ns, r.LatencyP99Ns)
	}
	if !r.Measured {
		t.Fatal("not measured")
	}
}

func TestExitNamesOnlyWhereTheNumberingIsKnown(t *testing.T) {
	cases := []struct {
		vendor string
		reason uint32
		want   string
	}{
		{"GenuineIntel", 12, "hlt"},
		{"GenuineIntel", 48, "ept_violation"},
		{"GenuineIntel", 30, "io_instruction"},
		{"GenuineIntel", 1<<31 | 33, "invalid_guest_state"}, // failed VM entry sets bit 31
		{"GenuineIntel", 9999, ""},                          // unknown stays unnamed
		{"AuthenticAMD", 12, ""},                            // SVM reuses small numbers for other things
		{"AuthenticAMD", 123, ""},
		{"", 12, ""}, // arm64 has no vendor_id, and reports an exception class
	}
	for _, c := range cases {
		if got := ExitName(c.vendor, c.reason); got != c.want {
			t.Errorf("ExitName(%q, %d) = %q, want %q", c.vendor, c.reason, got, c.want)
		}
	}
	rows := []KVMRow{{Top: []Reason{{Reason: 12}}, TopByTime: []Reason{{Reason: 48}}}}
	NameReasons(rows, "GenuineIntel")
	if rows[0].Top[0].Name != "hlt" || rows[0].TopByTime[0].Name != "ept_violation" {
		t.Fatalf("%+v", rows)
	}
	NameReasons(rows, "AuthenticAMD")
	if rows[0].Top[0].Name != "" || rows[0].TopByTime[0].Name != "" {
		t.Fatalf("names survived a vendor change: %+v", rows)
	}
}
