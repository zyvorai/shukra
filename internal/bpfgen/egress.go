package bpfgen

import (
	"bytes"
	"net/netip"
	"sort"
)

// Egress policy modes, as the tap program keeps them in the second byte of a tap's tap_policy value.
const (
	EgressOff     uint8 = 0
	EgressAudit   uint8 = 1 // count what would be dropped, drop nothing
	EgressEnforce uint8 = 2
)

// EgressStat is the sum over CPUs of what one tap's egress policy did. Checked is every new connection or
// datagram it judged; Audit is what it would have dropped, and Drop what it did.
type EgressStat struct {
	Checked, AuditPkts, AuditBytes, DropPkts, DropBytes uint64
}

// egressStatC mirrors struct egress_stat in bpf/tap.bpf.c.
type egressStatC struct {
	Checked, AuditPkts, AuditBytes, DropPkts, DropBytes uint64
}

// egress4Key and egress6Key mirror struct egress4_key and egress6_key. Prefixlen is 32, for the ifindex which
// is matched whole, plus the length of the network.
type egress4Key struct {
	Prefixlen uint32
	Ifindex   uint32
	Addr      [4]byte
}

type egress6Key struct {
	Prefixlen uint32
	Ifindex   uint32
	Addr      [16]byte
}

// egressKeys turns a tap's allowed networks into its trie keys. A network is made canonical (its host bits
// cleared) and an IPv4 network written as an IPv4-mapped IPv6 one is IPv4. Each network appears once, in a
// fixed order.
func egressKeys(ifindex uint32, prefixes []netip.Prefix) ([]egress4Key, []egress6Key) {
	seen4 := map[egress4Key]bool{}
	seen6 := map[egress6Key]bool{}
	var k4 []egress4Key
	var k6 []egress6Key
	for _, p := range prefixes {
		a := p.Addr()
		bits := p.Bits()
		if a.Is4In6() {
			a, bits = a.Unmap(), bits-96
		}
		// An invalid prefix, and one written as IPv4-mapped that is wider than IPv4's own address space (bits
		// below zero after the mapping), have no canonical form, and are left out.
		masked, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if masked.Addr().Is4() {
			k := egress4Key{Prefixlen: 32 + uint32(bits), Ifindex: ifindex, Addr: masked.Addr().As4()}
			if !seen4[k] {
				seen4[k] = true
				k4 = append(k4, k)
			}
			continue
		}
		k := egress6Key{Prefixlen: 32 + uint32(bits), Ifindex: ifindex, Addr: masked.Addr().As16()}
		if !seen6[k] {
			seen6[k] = true
			k6 = append(k6, k)
		}
	}
	sort.Slice(k4, func(i, j int) bool {
		if c := bytes.Compare(k4[i].Addr[:], k4[j].Addr[:]); c != 0 {
			return c < 0
		}
		return k4[i].Prefixlen < k4[j].Prefixlen
	})
	sort.Slice(k6, func(i, j int) bool {
		if c := bytes.Compare(k6[i].Addr[:], k6[j].Addr[:]); c != 0 {
			return c < 0
		}
		return k6[i].Prefixlen < k6[j].Prefixlen
	})
	return k4, k6
}
