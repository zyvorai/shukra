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
	return 0;
}

SEC("tracepoint/kvm/kvm_entry")
int shukra_kvm_entry(struct shukra_kvm_common *ctx) {
	(void)ctx;
	__u32 pid = cur_pid();
	bump(&pid, &kvm_entries);
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
