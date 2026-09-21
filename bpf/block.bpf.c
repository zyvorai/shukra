//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct blk_start {
	__u64 insert_ns; /* queued, before the device sees it. 0 if issue was seen first */
	__u64 issue_ns;  /* dispatched to the device. 0 until block_rq_issue */
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

/* Time from insert to issue: sitting in the host queue, not on the device. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct hist_key);
	__type(value, __u64);
} blk_qhist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} blk_issues SEC(".maps");

struct io_key {
	__u32 pid;
	__u32 write;
};

struct io_val {
	__u64 ops;
	__u64 bytes;
	__u64 max_ns;
	__u64 errors; /* completed with a non-zero status */
};

/* Completed requests, bytes and the slowest request, per issuing task and direction. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct io_key);
	__type(value, struct io_val);
} blk_io SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void hist_bump(void *map, __u32 pid, __u8 write, __u64 ns) {
	struct hist_key hk = {.pid = pid, .write = write, .bucket = (__u8)log2_bucket(ns)};
	__u64 *c = bpf_map_lookup_elem(map, &hk);
	if (c) {
		__sync_fetch_and_add(c, 1);
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(map, &hk, &one, BPF_NOEXIST);
}

SEC("tracepoint/block/block_rq_insert")
int shukra_rq_insert(struct trace_event_raw_block_rq *ctx) {
	struct blk_key key = {};
	key.dev = BPF_CORE_READ(ctx, dev);
	key.sector = BPF_CORE_READ(ctx, sector);
	__u64 now = bpf_ktime_get_ns();
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	__u8 write = ctx->rwbs[0] == 'W';
	struct blk_start *cur = bpf_map_lookup_elem(&blk_inflight, &key);
	if (cur) {
		if (cur->insert_ns == 0)
			cur->insert_ns = now;
		return 0;
	}
	struct blk_start st = {};
	st.insert_ns = now;
	st.pid = pid;
	st.write = write;
	bpf_map_update_elem(&blk_inflight, &key, &st, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_issue")
int shukra_rq_issue(struct trace_event_raw_block_rq *ctx) {
	struct blk_key key = {};
	key.dev = BPF_CORE_READ(ctx, dev);
	key.sector = BPF_CORE_READ(ctx, sector);
	__u64 now = bpf_ktime_get_ns();
	struct blk_start *cur = bpf_map_lookup_elem(&blk_inflight, &key);
	__u32 issuer = (__u32)bpf_get_current_pid_tgid();
	if (cur) {
		__u32 qpid = cur->pid;
		__u8 qwrite = cur->write;
		__u64 ins = cur->insert_ns;
		if (qpid != 0)
			issuer = qpid;
		if (ins != 0 && now > ins)
			hist_bump(&blk_qhist, issuer, qwrite, now - ins);
		cur = bpf_map_lookup_elem(&blk_inflight, &key);
		if (cur) {
			cur->issue_ns = now;
			if (cur->pid == 0)
				cur->pid = issuer;
		}
	} else {
		struct blk_start st = {};
		st.issue_ns = now;
		st.pid = issuer;
		st.write = ctx->rwbs[0] == 'W';
		bpf_map_update_elem(&blk_inflight, &key, &st, BPF_ANY);
	}
	__u64 *n = bpf_map_lookup_elem(&blk_issues, &issuer);
	if (n)
		__sync_fetch_and_add(n, 1);
	else {
		__u64 one = 1;
		bpf_map_update_elem(&blk_issues, &issuer, &one, BPF_NOEXIST);
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
	__u64 issue_ns = st->issue_ns;
	__u64 insert_ns = st->insert_ns;
	__u32 pid = st->pid;
	__u8 write = st->write;
	bpf_map_delete_elem(&blk_inflight, &key);
	__u64 now = bpf_ktime_get_ns();
	__u64 d = 0;
	__u64 start = issue_ns != 0 ? issue_ns : insert_ns;
	if (start != 0 && now > start)
		d = now - start;
	int status = BPF_CORE_READ(ctx, error);
	__u64 nbytes = (__u64)BPF_CORE_READ(ctx, nr_sector) * 512;
	hist_bump(&blk_hist, pid, write, d);
	struct io_key ik = {.pid = pid, .write = write};
	struct io_val *iv = bpf_map_lookup_elem(&blk_io, &ik);
	if (!iv) {
		struct io_val zero = {};
		bpf_map_update_elem(&blk_io, &ik, &zero, BPF_NOEXIST);
		iv = bpf_map_lookup_elem(&blk_io, &ik);
	}
	if (iv) {
		__sync_fetch_and_add(&iv->ops, 1);
		__sync_fetch_and_add(&iv->bytes, nbytes);
		/* Not atomic: two CPUs racing here can drop a slightly smaller maximum. */
		if (d > iv->max_ns)
			iv->max_ns = d;
		if (status != 0)
			__sync_fetch_and_add(&iv->errors, 1);
	}
	if (d >= BLOCK_SLOW_NS) {
		struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (!e)
			return 0;
		__builtin_memset(e, 0, sizeof(*e));
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
