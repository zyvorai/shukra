package bpfgen

import (
	"net/netip"
	"reflect"
	"testing"
)

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnIPv4NetworkIsTheInterfaceThenTheNetwork(t *testing.T) {
	k4, k6 := egressKeys(7, []netip.Prefix{pfx(t, "203.0.113.0/24"), pfx(t, "198.51.100.7/32"), pfx(t, "0.0.0.0/0")})
	want := []egress4Key{
		{Prefixlen: 32, Ifindex: 7, Addr: [4]byte{0, 0, 0, 0}},
		{Prefixlen: 64, Ifindex: 7, Addr: [4]byte{198, 51, 100, 7}},
		{Prefixlen: 56, Ifindex: 7, Addr: [4]byte{203, 0, 113, 0}},
	}
	if !reflect.DeepEqual(k4, want) || len(k6) != 0 {
		t.Fatalf("got %+v %+v\nwant %+v", k4, k6, want)
	}
}

func TestAnIPv6NetworkIsTheInterfaceThenTheNetwork(t *testing.T) {
	_, k6 := egressKeys(3, []netip.Prefix{pfx(t, "2001:db8::/32"), pfx(t, "2001:db9:1::5/128"), pfx(t, "::/0")})
	if len(k6) != 3 {
		t.Fatalf("%+v", k6)
	}
	byBits := map[uint32]egress6Key{}
	for _, k := range k6 {
		if k.Ifindex != 3 {
			t.Fatalf("the key names another tap: %+v", k)
		}
		byBits[k.Prefixlen] = k
	}
	a64, a160 := byBits[64].Addr, byBits[160].Addr
	if byBits[32].Addr != [16]byte{} || a64[0] != 0x20 || a64[3] != 0xb8 || a160[15] != 5 {
		t.Fatalf("%+v", byBits)
	}
}

func TestHostBitsAreClearedSoTwoSpellingsOfANetworkAreOne(t *testing.T) {
	k4, _ := egressKeys(1, []netip.Prefix{pfx(t, "203.0.113.9/24"), pfx(t, "203.0.113.200/24"), pfx(t, "203.0.113.0/24")})
	if len(k4) != 1 || k4[0].Addr != [4]byte{203, 0, 113, 0} || k4[0].Prefixlen != 56 {
		t.Fatalf("%+v", k4)
	}
	_, k6 := egressKeys(1, []netip.Prefix{pfx(t, "2001:db8:ffff::1/32"), pfx(t, "2001:db8::/32")})
	if len(k6) != 1 {
		t.Fatalf("%+v", k6)
	}
}

func TestAnIPv4MappedNetworkIsAnIPv4OneAndOneWiderThanIPv4IsNeither(t *testing.T) {
	k4, k6 := egressKeys(1, []netip.Prefix{pfx(t, "::ffff:203.0.113.0/120"), pfx(t, "::ffff:0.0.0.0/64")})
	if len(k6) != 0 || len(k4) != 1 || k4[0].Prefixlen != 56 || k4[0].Addr != [4]byte{203, 0, 113, 0} {
		t.Fatalf("%+v %+v", k4, k6)
	}
}

func TestTheKeysComeOutOnceAndInAFixedOrder(t *testing.T) {
	in := []netip.Prefix{pfx(t, "10.2.0.0/16"), pfx(t, "10.1.0.0/16"), pfx(t, "10.2.0.0/16"), pfx(t, "10.1.0.0/24"), {}}
	a, _ := egressKeys(9, in)
	b, _ := egressKeys(9, []netip.Prefix{in[3], in[1], in[0], in[2]})
	if len(a) != 3 || !reflect.DeepEqual(a, b) {
		t.Fatalf("%+v\n%+v", a, b)
	}
	if a[0].Addr != [4]byte{10, 1, 0, 0} || a[0].Prefixlen != 48 || a[1].Prefixlen != 56 || a[2].Addr != [4]byte{10, 2, 0, 0} {
		t.Fatalf("%+v", a)
	}
}
