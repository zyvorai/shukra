//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "event.h"
/* tcp_retransmit_skb is not a complete type in vmlinux BTF on 6.17.
   Layout is the 6.8 trace format, packed so saddr stays at offset 34. */
struct shukra_tcp_retrans {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	__u64 skbaddr;
	__u64 skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} __attribute__((packed));

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} net_retrans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Connect attempts per task, both families. Counted here, in the kernel, so the
   total does not depend on how many events the ring delivered. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} net_connects SEC(".maps");

static __always_inline void bump_connects(void) {
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	__u64 *n = bpf_map_lookup_elem(&net_connects, &pid);
	if (n) {
		__sync_fetch_and_add(n, 1);
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(&net_connects, &pid, &one, BPF_NOEXIST);
}

/* dst6 is NULL for IPv4. */
static __always_inline void emit_net(__u32 kind, __u32 dst_be, const __u8 *dst6, __u16 dport) {
	struct ring_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	/* Reserved ring memory is not zeroed. */
	__builtin_memset(e, 0, sizeof(*e));
	__u64 id = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (__u32)id;
	e->tgid = id >> 32;
	e->kind = kind;
	e->dport = dport;
	if (dst6) {
		e->family = FAMILY_INET6;
		__builtin_memcpy(e->dst6, dst6, 16);
	} else {
		e->family = FAMILY_INET;
		e->dst_be = dst_be;
	}
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(shukra_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr) {
	struct sockaddr_in addr = {};
	if (bpf_probe_read_kernel(&addr, sizeof(addr), uaddr) < 0)
		return 0;
	bump_connects();
	emit_net(KIND_TCP_CONNECT, addr.sin_addr.s_addr, 0, __builtin_bswap16(addr.sin_port));
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(shukra_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr) {
	struct sockaddr_in6 addr = {};
	if (bpf_probe_read_kernel(&addr, sizeof(addr), uaddr) < 0)
		return 0;
	/* A v4-mapped address (::ffff:a.b.c.d) on a dual-stack socket is handed on to
	   tcp_v4_connect, whose kprobe counts it. Skip it here or it counts twice. */
	const __u8 *a = addr.sin6_addr.in6_u.u6_addr8;
	if (!(a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7] | a[8] | a[9]) && a[10] == 0xff && a[11] == 0xff)
		return 0;
	bump_connects();
	emit_net(KIND_TCP_CONNECT, 0, a, __builtin_bswap16(addr.sin6_port));
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int shukra_retrans(struct shukra_tcp_retrans *ctx) {
	__u32 pid = (__u32)bpf_get_current_pid_tgid();
	__u64 *n = bpf_map_lookup_elem(&net_retrans, &pid);
	if (n)
		__sync_fetch_and_add(n, 1);
	else {
		__u64 one = 1;
		bpf_map_update_elem(&net_retrans, &pid, &one, BPF_NOEXIST);
	}
	/* One in 64 retransmits becomes a flight-recorder sample, not every skb. */
	if ((bpf_get_prandom_u32() & 63) != 0)
		return 0;
	__u16 dport = ctx->dport;
	if (ctx->family == FAMILY_INET6) {
		emit_net(KIND_TCP_RETRANS, 0, ctx->daddr_v6, dport);
		return 0;
	}
	__u32 dst = ((__u32)ctx->daddr[0]) |
		    ((__u32)ctx->daddr[1] << 8) |
		    ((__u32)ctx->daddr[2] << 16) |
		    ((__u32)ctx->daddr[3] << 24);
	emit_net(KIND_TCP_RETRANS, dst, 0, dport);
	return 0;
}
