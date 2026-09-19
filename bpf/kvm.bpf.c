//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "event.h"

/* KVM trace records are absent from vmlinux BTF on Linux 6.8. The common
   header is 8 bytes and exit_reason is the first payload field, matching
   /sys/kernel/tracing/events/kvm/kvm_exit/format. Do not CO-RE these. */
struct shukra_kvm_exit {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	__u32 exit_reason;
};

struct shukra_kvm_common {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct kvm_key {
	__u32 pid;
	__u32 reason;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct kvm_key);
	__type(value, __u64);
} kvm_exits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} kvm_entries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} kvm_mmio SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} kvm_pio SEC(".maps");

/* Exit handling time: kvm_exit to the next kvm_entry on the same vCPU thread. It is
   the time the host spends servicing the exit, including a round trip to QEMU for
   an MMIO or PIO access. */
struct exit_start {
	__u64 ts;
	__u32 reason;
	__u32 pad;
};

struct kvm_hkey {
	__u32 pid;
	__u32 bucket;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct exit_start);
} kvm_exit_start SEC(".maps");

/* Handling-time histogram per vCPU thread, log2 ns. Halts are left out. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct kvm_hkey);
	__type(value, __u64);
} kvm_lat SEC(".maps");

/* Total handling time per exit reason, halts included. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct kvm_key);
	__type(value, __u64);
} kvm_reason_ns SEC(".maps");

/* A halt blocks the vCPU until an interrupt arrives, so its duration is guest idle
   time and not handling latency. VMX reports HLT as 12 and SVM as 120. The two
   numbering schemes do not use the other's value for anything a guest triggers. */
#define EXIT_HLT_VMX 12
#define EXIT_HLT_SVM 120

static __always_inline void add_u64(void *map, void *key, __u64 delta) {
	__u64 *v = bpf_map_lookup_elem(map, key);
	if (v) {
		__sync_fetch_and_add(v, delta);
		return;
	}
	bpf_map_update_elem(map, key, &delta, BPF_NOEXIST);
}

static __always_inline void bump(__u32 *key, void *map) {
	__u64 *v = bpf_map_lookup_elem(map, key);
	if (v) {
		__sync_fetch_and_add(v, 1);
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
}

static __always_inline __u32 cur_pid(void) {
	return (__u32)bpf_get_current_pid_tgid();
}

SEC("tracepoint/kvm/kvm_exit")
int shukra_kvm_exit(struct shukra_kvm_exit *ctx) {
	struct kvm_key key = {};
	key.pid = cur_pid();
	key.reason = ctx->exit_reason;
	__u64 *v = bpf_map_lookup_elem(&kvm_exits, &key);
	if (v) {
		__sync_fetch_and_add(v, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&kvm_exits, &key, &one, BPF_NOEXIST);
	}
	struct exit_start st = {.ts = bpf_ktime_get_ns(), .reason = key.reason};
	bpf_map_update_elem(&kvm_exit_start, &key.pid, &st, BPF_ANY);
	return 0;
}

SEC("tracepoint/kvm/kvm_entry")
int shukra_kvm_entry(struct shukra_kvm_common *ctx) {
	(void)ctx;
	__u32 pid = cur_pid();
	bump(&pid, &kvm_entries);
	struct exit_start *st = bpf_map_lookup_elem(&kvm_exit_start, &pid);
	if (!st)
		return 0; /* the first entry after a vCPU starts has no exit before it */
	__u64 start = st->ts;
	__u32 reason = st->reason;
	bpf_map_delete_elem(&kvm_exit_start, &pid);
	__u64 now = bpf_ktime_get_ns();
	if (now <= start)
		return 0;
	__u64 d = now - start;
	struct kvm_key rk = {.pid = pid, .reason = reason};
	add_u64(&kvm_reason_ns, &rk, d);
	if (reason == EXIT_HLT_VMX || reason == EXIT_HLT_SVM)
		return 0;
	struct kvm_hkey hk = {.pid = pid, .bucket = log2_bucket(d)};
	add_u64(&kvm_lat, &hk, 1);
	return 0;
}

SEC("tracepoint/kvm/kvm_mmio")
int shukra_kvm_mmio(struct shukra_kvm_common *ctx) {
	(void)ctx;
	__u32 pid = cur_pid();
	bump(&pid, &kvm_mmio);
	return 0;
}

SEC("tracepoint/kvm/kvm_pio")
int shukra_kvm_pio(struct shukra_kvm_common *ctx) {
	(void)ctx;
	__u32 pid = cur_pid();
	bump(&pid, &kvm_pio);
	return 0;
}
