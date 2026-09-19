//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* skb:kfree_skb is read through the kernel's own description of it, struct trace_event_raw_kfree_skb from
   vmlinux BTF, so CO-RE finds skbaddr, location and reason wherever this kernel puts them. Linux 6.9 added a
   field (rx_sk) in front of protocol and reason and moved them, which a hand-written layout would have read
   wrongly. A kernel with no drop reason (before 5.17) has no such field and the program fails to load, which
   internal/bpfgen/drops.go reports in words before it tries. */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Interfaces worth counting: the VM taps. Userspace keeps this equal to the set of taps the tap
   program is on. Everything else is one failed lookup, because kfree_skb runs for every packet
   the host drops, and on a busy hypervisor that is a lot. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* ifindex */
	__type(value, __u8);
} drop_watch SEC(".maps");

struct drop_key {
	__u32 ifindex;
	__u32 reason;
};

#define SYM_LEN 48

struct drop_val {
	__u64 count;
	__u64 location;      /* the last kernel address that freed one */
	char sym[SYM_LEN];   /* the function at the FIRST free seen for this key on this CPU, named by the kernel */
};

/* %ps asks the kernel itself to name the function, so this needs no CAP_SYSLOG and no /proc/kallsyms.
   It runs once per new key, not per packet: the hot path is a lookup and an increment. */
static const char fmt_sym[] = "%ps";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct drop_key);
	__type(value, struct drop_val);
} drop_stats SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int drops_kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (!skb)
		return 0;
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	if (!dev)
		return 0;
	__u32 ifindex = BPF_CORE_READ(dev, ifindex);
	if (!bpf_map_lookup_elem(&drop_watch, &ifindex))
		return 0;

	struct drop_key k = {.ifindex = ifindex, .reason = ctx->reason};
	struct drop_val *v = bpf_map_lookup_elem(&drop_stats, &k);
	if (v) {
		v->count++;
		v->location = (__u64)ctx->location;
		return 0;
	}
	struct drop_val fresh = {.count = 1, .location = (__u64)ctx->location};
	__u64 args[1] = {(__u64)ctx->location};
	bpf_snprintf(fresh.sym, sizeof(fresh.sym), fmt_sym, args, sizeof(args));
	bpf_map_update_elem(&drop_stats, &k, &fresh, BPF_NOEXIST);
	return 0;
}
