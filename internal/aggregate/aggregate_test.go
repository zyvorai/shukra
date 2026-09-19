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
