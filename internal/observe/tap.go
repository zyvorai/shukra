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
}

// tap event, decoded by offset. bpf/tap.bpf.c asserts this size at compile time.
//
//	 0 ts_ns u64   8 ifindex u32  12 dport u16  14 sport u16  16 family u8  17 dropped u8
//	24 src [16]    40 dst [16]                                              = 56
const tapEventSize = 56
