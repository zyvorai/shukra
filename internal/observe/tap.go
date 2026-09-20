package observe

// TapCounters is one VM tap's traffic, from the guest's point of view: From is
// what the guest sent, To is what was sent to it. Dropped is what isolation
// discarded, in either direction.
type TapCounters struct {
	Name         string
	Ifindex      uint32
	FromPkts     uint64
	FromBytes    uint64
	ToPkts       uint64
	ToBytes      uint64
	DroppedPkts  uint64
	DroppedBytes uint64
	Isolated     bool

	// Handshake outcomes of the TCP connections on this tap. Out is the guest's own, In is made to it.
	OutSyn, OutOK, OutRefused, OutTimeout, OutRetrans, OutBlocked uint64
	InSyn, InOK, InRefused, InIgnored, InRetrans, InBlocked       uint64
	// HandshakeHist is how long the guest's connections took to be answered, log2 ns.
	HandshakeHist []uint64
}

// tap event, decoded by offset. bpf/tap.bpf.c asserts this size at compile time.
//
//	 0 ts_ns u64   8 ifindex u32  12 dport u16  14 sport u16  16 family u8  17 dropped u8  18 proto u8  19 dir u8
//	20 policy u8  24 src [16]    40 dst [16]                                                            = 56
const tapEventSize = 56

// policyName names the egress policy's verdict byte of a connect event: 1 is a connection outside the policy
// that audit mode let through, 2 one that enforcement dropped. Anything else, including a program from before
// egress policy (which left the byte zero), is no verdict.
func policyName(b byte) string {
	switch b {
	case 1:
		return "audit"
	case 2:
		return "enforce"
	}
	return ""
}

// EgressCounters is what one tap's egress policy has done: its mode (0 off, 1 audit, 2 enforce), how many new
// connections and datagrams it judged, what audit mode would have dropped and what enforcement did.
type EgressCounters struct {
	Tap                                                 string
	Mode                                                uint8
	Checked, AuditPkts, AuditBytes, DropPkts, DropBytes uint64
}
