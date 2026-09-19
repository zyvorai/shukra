//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct blk_start {
	__u64 ts_ns;
	__u32 pid;
	__u8 write;
};

struct blk_key {
	__u32 dev;
	__u64 sector;
};

struct hist_key {
	__u32 pid;
	__u8 write;
	__u8 bucket;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct blk_key);
	__type(value, struct blk_start);
} blk_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct hist_key);
	__type(value, __u64);
} blk_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} blk_issues SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void hist_add(__u32 pid, __u8 write, __u64 ns) {
	__u8 bucket = 0;
	__u64 v = ns;
	while (v > 1 && bucket < 63) {
		v >>= 1;
		bucket++;
	}
	struct hist_key hk = {.pid = pid, .write = write, .bucket = bucket};
	__u64 *c = bpf_map_lookup_elem(&blk_hist, &hk);
	if (c) {
		__sync_fetch_and_add(c, 1);
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(&blk_hist, &hk, &one, BPF_NOEXIST);
}

SEC("tracepoint/block/block_rq_issue")
int shukra_rq_issue(struct trace_event_raw_block_rq *ctx) {
	struct blk_key key = {};
	key.dev = BPF_CORE_READ(ctx, dev);
	key.sector = BPF_CORE_READ(ctx, sector);
	struct blk_start st = {};
	st.ts_ns = bpf_ktime_get_ns();
	st.pid = (__u32)bpf_get_current_pid_tgid();
	st.write = ctx->rwbs[0] == 'W';
	bpf_map_update_elem(&blk_inflight, &key, &st, BPF_ANY);
	__u64 *n = bpf_map_lookup_elem(&blk_issues, &st.pid);
	if (n)
		__sync_fetch_and_add(n, 1);
	else {
		__u64 one = 1;
		bpf_map_update_elem(&blk_issues, &st.pid, &one, BPF_NOEXIST);
	}
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int shukra_rq_complete(struct trace_event_raw_block_rq_completion *ctx) {
	struct blk_key key = {};
	key.dev = BPF_CORE_READ(ctx, dev);
	key.sector = BPF_CORE_READ(ctx, sector);
	struct blk_start *st = bpf_map_lookup_elem(&blk_inflight, &key);
	if (!st)
		return 0;
	__u64 now = bpf_ktime_get_ns();
	__u64 d = 0;
	if (now > st->ts_ns)
		d = now - st->ts_ns;
	__u32 pid = st->pid;
	__u8 write = st->write;
	bpf_map_delete_elem(&blk_inflight, &key);
	hist_add(pid, write, d);
	if (d >= BLOCK_SLOW_NS) {
		struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;
		e->ts_ns = now;
		e->pid = pid;
		e->tgid = bpf_get_current_pid_tgid() >> 32;
		e->kind = KIND_BLOCK_SLOW;
		e->aux_ns = d;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
