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
