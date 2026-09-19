package observe

import (
	"strings"
	"testing"
)

func TestAReasonIsShownWithoutTheKernelPrefixAndNeverGuessed(t *testing.T) {
	names := map[uint32]string{51: "SKB_DROP_REASON_TC_INGRESS", 62: "SKB_DROP_REASON_FULL_RING"}
	if got := dropReasonLabel(names, 51); got != "TC_INGRESS" {
		t.Fatalf("%q", got)
	}
	if got := dropReasonLabel(names, 62); got != "FULL_RING" {
		t.Fatalf("%q", got)
	}
	if got := dropReasonLabel(names, 999); got != "reason 999" {
		t.Fatalf("an unknown code was named: %q", got)
	}
	if got := dropReasonLabel(nil, 51); got != "reason 51" {
		t.Fatalf("with no names read, the number is shown: %q", got)
	}
}

const kallsyms = `ffffffff81000000 T _stext
ffffffff81234560 T __netif_receive_skb_core
ffffffff81234ff0 t some_static_helper
ffffffff81235000 T next_function
ffffffff81236000 d a_data_symbol
ffffffffc0a01000 t vhost_net_module_fn	[vhost_net]
`

func TestTheKernelFunctionContainingAnAddressIsFound(t *testing.T) {
	sym, ok := nearestSymbol(strings.NewReader(kallsyms), 0xffffffff81234a00)
	if !ok || sym != "__netif_receive_skb_core" {
		t.Fatalf("%q %v", sym, ok)
	}
	sym, ok = nearestSymbol(strings.NewReader(kallsyms), 0xffffffff81235010)
	if !ok || sym != "next_function" {
		t.Fatalf("the data symbol after it must not win: %q %v", sym, ok)
	}
}

func TestHiddenKernelAddressesAreSaidNotInvented(t *testing.T) {
	hidden := "0000000000000000 T _stext\n0000000000000000 T __netif_receive_skb_core\n"
	if sym, ok := nearestSymbol(strings.NewReader(hidden), 0xffffffff81234a00); ok {
		t.Fatalf("resolved from zero addresses: %q", sym)
	}
	if got := locationLabel("", false, 0xffffffff81234a00); got != "0xffffffff81234a00" {
		t.Fatalf("an address that cannot be resolved is shown as the address: %q", got)
	}
	if got := locationLabel("", false, 0); got != "" {
		t.Fatalf("no location is empty: %q", got)
	}
	if got := locationLabel("f", true, 5); got != "f" {
		t.Fatalf("%q", got)
	}
}
