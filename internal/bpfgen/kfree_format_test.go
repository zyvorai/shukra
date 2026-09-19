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

func TestAMovedFieldIsRefusedNotReadAtTheWrongOffset(t *testing.T) {
	moved := strings.Replace(kfreeFormat68, "offset:28", "offset:32", 1)
	err := checkKfreeSkbFormat(moved)
	if err == nil || !strings.Contains(err.Error(), "reason at offset 32") || !strings.Contains(err.Error(), "expects 28") {
		t.Fatalf("%v", err)
	}
}

func TestNothingReadableIsRefused(t *testing.T) {
	if err := checkKfreeSkbFormat(""); err == nil || !strings.Contains(err.Error(), "no readable format") {
		t.Fatalf("%v", err)
	}
}
