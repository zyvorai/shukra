#ifndef __SHUKRA_EVENT_H
#define __SHUKRA_EVENT_H

#define KIND_EXEC 1
#define KIND_TCP_CONNECT 2
#define KIND_TCP_RETRANS 3
#define KIND_BLOCK_SLOW 4
#define KIND_SCHED_DELAY 5
#define KIND_EXIT 6

/* Sample a slow block request or a long wakeup into the ring. Counters stay in maps. */
#define BLOCK_SLOW_NS 10000000ull
#define SCHED_DELAY_NS 20000000ull

/* Slot for a latency in ns: bits.Len64(v)-1, and 0 for v <= 1. Mirrors
   internal/hist.Bucket so userspace percentiles read the same buckets. */
static __always_inline __u32 log2_bucket(__u64 v) {
	__u32 r = 0;
	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

struct ring_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tgid;
	__u32 kind;
	__u16 dport;
	__u32 dst_be;
	__u64 aux_ns;
	__u8 comm[16];
};

#endif
