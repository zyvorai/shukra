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
