//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sched_val {
	__u64 oncpu_ns;
	__u64 wakeup_delay_ns;
	__u64 wakeup_count;
	__u64 last_on_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct sched_val);
} sched_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} wakeup_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct sched_val *stat(__u32 pid) {
	struct sched_val *v = bpf_map_lookup_elem(&sched_stats, &pid);
	if (v)
		return v;
	struct sched_val zero = {};
	bpf_map_update_elem(&sched_stats, &pid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&sched_stats, &pid);
}

static __always_inline void emit(__u32 kind, __u32 pid, __u64 aux) {
	struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	e->kind = kind;
	e->aux_ns = aux;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/sched/sched_wakeup")
int shukra_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
	__u32 pid = BPF_CORE_READ(ctx, pid);
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int shukra_switch(struct trace_event_raw_sched_switch *ctx) {
	__u64 now = bpf_ktime_get_ns();
	__u32 prev = BPF_CORE_READ(ctx, prev_pid);
	__u32 next = BPF_CORE_READ(ctx, next_pid);
	struct sched_val *ps = stat(prev);
	if (ps && ps->last_on_ns && now > ps->last_on_ns)
		__sync_fetch_and_add(&ps->oncpu_ns, now - ps->last_on_ns);
	struct sched_val *ns = stat(next);
	if (ns)
		ns->last_on_ns = now;
	__u64 *woke = bpf_map_lookup_elem(&wakeup_ts, &next);
	if (woke && ns && now > *woke) {
		__u64 d = now - *woke;
		__sync_fetch_and_add(&ns->wakeup_delay_ns, d);
		__sync_fetch_and_add(&ns->wakeup_count, 1);
		bpf_map_delete_elem(&wakeup_ts, &next);
		if (d >= SCHED_DELAY_NS)
			emit(KIND_SCHED_DELAY, next, d);
	}
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int shukra_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	emit(KIND_EXEC, pid, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int shukra_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = BPF_CORE_READ(ctx, pid);
	bpf_map_delete_elem(&sched_stats, &pid);
	bpf_map_delete_elem(&wakeup_ts, &pid);
	emit(KIND_EXIT, pid, 0);
	return 0;
}
