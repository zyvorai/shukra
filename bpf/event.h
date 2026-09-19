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

#define FAMILY_INET 2
#define FAMILY_INET6 10

/* One discrete event. Userspace decodes this by offset (internal/observe/decode.go),
   so every field is explicitly placed and there is no implicit padding. */
struct ring_event {
	__u64 ts_ns;    /* 0 */
	__u32 pid;      /* 8 */
	__u32 tgid;     /* 12 */
	__u32 kind;     /* 16 */
	__u16 dport;    /* 20 */
	__u16 family;   /* 22: FAMILY_INET or FAMILY_INET6 for network events, else 0 */
	__u32 dst_be;   /* 24: IPv4 destination, network order */
	__u32 ppid;     /* 28: tgid of the parent process, for exec and exit, else 0 */
	__u64 aux_ns;   /* 32 */
	__u8 comm[16];  /* 40 */
	__u8 dst6[16];  /* 56: IPv6 destination when family is FAMILY_INET6 */
};                      /* 72 */

_Static_assert(sizeof(struct ring_event) == 72, "ring_event layout changed: update internal/observe/decode.go");

#endif
