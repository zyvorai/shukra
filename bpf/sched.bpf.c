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
	__u64 preempt_ns;    /* time spent runnable but off CPU after being preempted */
	__u64 preempt_count;
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

/* A watched task that is switched out while still runnable was preempted: it wanted the CPU and something
   else got it. The wait ends when the task is switched in again. The map holds who took the CPU (next_pid
   and its comm) from the moment of preemption, keyed by the preempted thread. It is small and LRU: only
   watched threads ever enter it, and one that never comes back is simply forgotten. */
struct preempt_start_val {
	__u64 ts;
	__u32 by_pid;
	char by_comm[16];
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct preempt_start_val);
} preempt_start SEC(".maps");

struct preempt_key {
	__u32 victim;
	__u32 by;
};

struct preempt_val {
	__u64 count;
	__u64 ns;
	char comm[16];
};

/* How long each watched thread waited, and for whom: {preempted thread, the thread that took its CPU}.
   The key includes the taker's thread id, which is unbounded on a busy host, so this is an LRU and the
   per-thread totals in sched_stats are the ones that are exact. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct preempt_key);
	__type(value, struct preempt_val);
} preempt_by SEC(".maps");

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

static __always_inline void emit(__u32 kind, __u32 pid, __u64 aux, __u32 ppid) {
	struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	/* Reserved ring memory is not zeroed. */
	__builtin_memset(e, 0, sizeof(*e));
	e->ppid = ppid;
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
			emit(KIND_SCHED_DELAY, next, d, 0);
	}

	/* This task is on a CPU again: if it had been preempted, the wait is over. */
	struct preempt_start_val *pst = bpf_map_lookup_elem(&preempt_start, &next);
	if (pst) {
		__u64 d = now > pst->ts ? now - pst->ts : 0;
		if (d && ns) {
			__sync_fetch_and_add(&ns->preempt_ns, d);
			__sync_fetch_and_add(&ns->preempt_count, 1);
			struct preempt_key pk = {.victim = next, .by = pst->by_pid};
			struct preempt_val *pv = bpf_map_lookup_elem(&preempt_by, &pk);
			if (pv) {
				__sync_fetch_and_add(&pv->ns, d);
				__sync_fetch_and_add(&pv->count, 1);
				/* A thread may rename itself after it starts, so the newest name is kept. */
				__builtin_memcpy(pv->comm, pst->by_comm, sizeof(pv->comm));
			} else {
				struct preempt_val nv = {.count = 1, .ns = d};
				__builtin_memcpy(nv.comm, pst->by_comm, sizeof(nv.comm));
				bpf_map_update_elem(&preempt_by, &pk, &nv, BPF_ANY);
			}
		}
		bpf_map_delete_elem(&preempt_start, &next);
	}

	/* This task is leaving a CPU. If it is still runnable (on_rq) and is a QEMU thread, it was preempted:
	   sleeping tasks are dequeued before the switch, so they never look like this. */
	if (prev != next) {
		struct task_struct *t = (struct task_struct *)bpf_get_current_task();
		if (BPF_CORE_READ(t, on_rq)) {
			__u32 tgid = BPF_CORE_READ(t, tgid);
			if (bpf_map_lookup_elem(&watched, &tgid)) {
				struct preempt_start_val st = {.ts = now, .by_pid = next};
				BPF_CORE_READ_STR_INTO(&st.by_comm, ctx, next_comm);
				bpf_map_update_elem(&preempt_start, &prev, &st, BPF_ANY);
			}
		}
	}
	return 0;
}

/* True when the current task is in a watched QEMU process, or was started by one. */
static __always_inline int in_watched_process(__u32 *ppid_out) {
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 ppid = BPF_CORE_READ(t, real_parent, tgid);
	*ppid_out = ppid;
	return bpf_map_lookup_elem(&watched, &tgid) || bpf_map_lookup_elem(&watched, &ppid);
}

SEC("tracepoint/sched/sched_process_exec")
int shukra_exec(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 ppid = 0;
	if (!in_watched_process(&ppid))
		return 0;
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	emit(KIND_EXEC, pid, 0, ppid);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int shukra_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = BPF_CORE_READ(ctx, pid);
	bpf_map_delete_elem(&sched_stats, &pid);
	bpf_map_delete_elem(&wakeup_ts, &pid);
	bpf_map_delete_elem(&preempt_start, &pid);
	/* The cleanup above is unconditional. Only the event is filtered. */
	__u32 ppid = 0;
	if (!in_watched_process(&ppid))
		return 0;
	emit(KIND_EXIT, pid, 0, ppid);
	return 0;
}
