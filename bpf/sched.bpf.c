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

/* Every task on the host passes through sched_switch, so these are sized for a
   busy hypervisor: an idle vCPU thread must not be evicted by other tasks. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct sched_val);
} sched_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} wakeup_ts SEC(".maps");

struct sched_hkey {
	__u32 pid;
	__u32 bucket;
};

/* Run-queue delay (wakeup to on-CPU) per task, as a log2 histogram. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct sched_hkey);
	__type(value, __u64);
} sched_hist SEC(".maps");

/* tgids of the QEMU processes. Userspace keeps this in step with its /proc scan.
   exec and exit events are only emitted for these processes and their children,
   so a busy host does not flood the ring with every fork. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} watched SEC(".maps");

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
		struct sched_hkey hk = {.pid = next, .bucket = log2_bucket(d)};
		__u64 *hc = bpf_map_lookup_elem(&sched_hist, &hk);
		if (hc) {
			__sync_fetch_and_add(hc, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&sched_hist, &hk, &one, BPF_NOEXIST);
		}
		if (d >= SCHED_DELAY_NS)
			emit(KIND_SCHED_DELAY, next, d);
	}
	return 0;
}

/* True when the current task is in a watched QEMU process, or was started by one. */
static __always_inline int in_watched_process(void) {
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 ppid = BPF_CORE_READ(t, real_parent, tgid);
	return bpf_map_lookup_elem(&watched, &tgid) || bpf_map_lookup_elem(&watched, &ppid);
}

SEC("tracepoint/sched/sched_process_exec")
int shukra_exec(struct trace_event_raw_sched_process_exec *ctx) {
	if (!in_watched_process())
		return 0;
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	emit(KIND_EXEC, pid, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int shukra_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = BPF_CORE_READ(ctx, pid);
	bpf_map_delete_elem(&sched_stats, &pid);
	bpf_map_delete_elem(&wakeup_ts, &pid);
	/* The cleanup above is unconditional. Only the event is filtered. */
	if (!in_watched_process())
		return 0;
	emit(KIND_EXIT, pid, 0);
	return 0;
}
