package bpfgen

import (
	"strings"
	"testing"
)

// The format file of skb:kfree_skb on Linux 6.8, as read from a real hypervisor.
const kfreeFormat68 = `name: kfree_skb
ID: 1652
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:void * skbaddr;	offset:8;	size:8;	signed:0;
	field:void * location;	offset:16;	size:8;	signed:0;
	field:unsigned short protocol;	offset:24;	size:2;	signed:0;
	field:enum skb_drop_reason reason;	offset:28;	size:4;	signed:0;

print fmt: "skbaddr=%p protocol=%u location=%pS reason: %s", REC->skbaddr, REC->protocol, REC->location, __print_symbolic(REC->reason, { 2, "NOT_SPECIFIED" })
`

func TestTheKernelsKfreeSkbLayoutIsRecognised(t *testing.T) {
	if err := checkKfreeSkbFormat(kfreeFormat68); err != nil {
		t.Fatal(err)
	}
}

func TestAKernelWithoutADropReasonIsRefusedWithTheReason(t *testing.T) {
	old := strings.Replace(kfreeFormat68, "\tfield:enum skb_drop_reason reason;\toffset:28;\tsize:4;\tsigned:0;\n", "", 1)
	err := checkKfreeSkbFormat(old)
	if err == nil || !strings.Contains(err.Error(), "no drop reason") || !strings.Contains(err.Error(), "5.17") {
		t.Fatalf("%v", err)
	}
}

// The same record on Linux 6.9 and newer, which put rx_sk in front of protocol and reason.
const kfreeFormat69 = `name: kfree_skb
ID: 1652
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:void * skbaddr;	offset:8;	size:8;	signed:0;
	field:void * location;	offset:16;	size:8;	signed:0;
	field:void * rx_sk;	offset:24;	size:8;	signed:0;
	field:unsigned short protocol;	offset:32;	size:2;	signed:0;
	field:enum skb_drop_reason reason;	offset:36;	size:4;	signed:0;
`

func TestALayoutWithTheFieldsMovedIsAcceptedBecauseTheProgramReadsThemByName(t *testing.T) {
	// A hand-written layout read this wrongly and was refused, which left the program off on any kernel from
	// 6.9, including GitHub's runners. It reads the fields through the kernel's own type now, so it must run.
	if err := checkKfreeSkbFormat(kfreeFormat69); err != nil {
		t.Fatalf("a kernel with rx_sk was refused: %v", err)
	}
}

func TestARecordMissingAFieldTheProgramNeedsIsRefusedWithTheName(t *testing.T) {
	noLoc := strings.Replace(kfreeFormat68, "\tfield:void * location;\toffset:16;\tsize:8;\tsigned:0;\n", "", 1)
	if err := checkKfreeSkbFormat(noLoc); err == nil || !strings.Contains(err.Error(), "no location field") {
		t.Fatalf("%v", err)
	}
}

func TestNothingReadableIsRefused(t *testing.T) {
	if err := checkKfreeSkbFormat(""); err == nil || !strings.Contains(err.Error(), "no readable format") {
		t.Fatalf("%v", err)
	}
}
