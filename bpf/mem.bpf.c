//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} reclaim_start SEC(".maps");

struct mem_hkey {
	__u32 pid;
	__u32 bucket;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct mem_hkey);
	__type(value, __u64);
} reclaim_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} reclaim_ns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} reclaim_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} oom_kills SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void add_u32(__u32 pid, void *map, __u64 n) {
	__u64 *c = bpf_map_lookup_elem(map, &pid);
	if (c) {
		__sync_fetch_and_add(c, n);
		return;
	}
	bpf_map_update_elem(map, &pid, &n, BPF_NOEXIST);
}

static __always_inline void emit(__u32 kind, __u32 pid, __u32 tgid, __u64 aux) {
	struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->tgid = tgid;
	e->kind = kind;
	e->aux_ns = aux;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int shukra_reclaim_begin(void *ctx) {
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&reclaim_start, &pid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int shukra_reclaim_end(void *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)id;
	__u32 tgid = id >> 32;
	__u64 *start = bpf_map_lookup_elem(&reclaim_start, &pid);
	if (!start)
		return 0;
	__u64 began = *start;
	bpf_map_delete_elem(&reclaim_start, &pid);
	__u64 now = bpf_ktime_get_ns();
	__u64 d = 0;
	if (now > began)
		d = now - began;
	struct mem_hkey hk = {.pid = pid, .bucket = log2_bucket(d)};
	__u64 *c = bpf_map_lookup_elem(&reclaim_hist, &hk);
	if (c)
		__sync_fetch_and_add(c, 1);
	else {
		__u64 one = 1;
		bpf_map_update_elem(&reclaim_hist, &hk, &one, BPF_NOEXIST);
	}
	add_u32(pid, &reclaim_ns, d);
	add_u32(pid, &reclaim_count, 1);
	if (d >= RECLAIM_SLOW_NS)
		emit(KIND_RECLAIM, pid, tgid, d);
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int shukra_oom(struct trace_event_raw_mark_victim *ctx) {
	__u32 victim = (__u32)BPF_CORE_READ(ctx, pid);
	if (victim == 0)
		return 0;
	add_u32(victim, &oom_kills, 1);
	emit(KIND_OOM, victim, victim, 0);
	return 0;
}
