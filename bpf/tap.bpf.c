//go:build ignore

/* Guest traffic, seen where it leaves and enters the VM: on the host side of the
   VM's tap interface. Unlike the host tcp_v4_connect probe, which sees QEMU's own
   sockets, a packet here really is the guest's, so events from this program are
   the only ones Shukra marks guest_attributed.

   Direction is named from the guest's point of view. TCX "ingress" on a tap is a
   frame the guest transmitted (from_guest); "egress" is a frame sent to it. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* TCX verdicts. TCX_NEXT hands the packet to the next program on the hook. TCX_PASS
   would accept it and stop the chain, skipping every program attached after this
   one: another tool's policy or monitoring on the same tap. An observer must not do
   that, so this program only ever returns NEXT or DROP. */
#define TCX_NEXT -1
#define TCX_DROP 2

/* pkt_type of a frame the host sent and the kernel looped back in. Multicast the
   host transmits is delivered again through the device's ingress hook, where it
   would otherwise be counted as a frame the guest sent. */
#define PACKET_LOOPBACK 5

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17
#define IPPROTO_ICMPV6_ 58

#define FAMILY_INET 2
#define FAMILY_INET6 10

/* At most this many connect events per tap per second. A guest that floods SYNs
   must not be able to flood the ring, and the counters still see every packet. */
#define EVENTS_PER_SEC 200

/* A UDP flow is announced once, then again only after it has been quiet or long
   lived for this long. A busy stream must not become a stream of events. */
#define UDP_FLOW_REFRESH_NS 60000000000ull

struct tap_stat {
	__u64 from_pkts;
	__u64 from_bytes;
	__u64 to_pkts;
	__u64 to_bytes;
	__u64 dropped_pkts;
	__u64 dropped_bytes;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* ifindex */
	__type(value, struct tap_stat);
} tap_stats SEC(".maps");

/* Set for an ifindex to isolate the VM behind it. */
struct tap_policy {
	__u8 isolated;
	__u8 pad[7];
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct tap_policy);
} tap_policy SEC(".maps");

/* Management networks an isolated VM may still exchange traffic with. Userspace
   refuses to isolate anything while these are empty. */
struct lpm4_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct lpm6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4_key);
	__type(value, __u8);
} allow4 SEC(".maps");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6_key);
	__type(value, __u8);
} allow6 SEC(".maps");

struct rate {
	__u64 window_ns;
	__u64 count;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct rate);
} tap_rate SEC(".maps");

/* UDP flows seen recently, so only a new flow produces an event. The key is made of
   values the guest controls, so this is an LRU with a fixed size: the guest cannot
   grow it, only turn it over. */
struct flow_key {
	__u32 ifindex;
	__u16 sport;
	__u16 dport;
	__u8 family;
	__u8 pad[3];
	__u8 src[16];
	__u8 dst[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, __u64);
} udp_flows SEC(".maps");

/* Decoded by offset in internal/observe/tap.go. Every field is placed explicitly. */
struct tap_event {
	__u64 ts_ns;    /* 0 */
	__u32 ifindex;  /* 8 */
	__u16 dport;    /* 12 */
	__u16 sport;    /* 14 */
	__u8 family;    /* 16 */
	__u8 dropped;   /* 17: 1 when isolation dropped this packet */
	__u8 proto;     /* 18: 6 for a TCP connect, 17 for a new UDP flow */
	__u8 pad[5];    /* 19 */
	__u8 src[16];   /* 24: IPv4 uses the first 4 bytes */
	__u8 dst[16];   /* 40 */
};                      /* 56 */

_Static_assert(sizeof(struct tap_event) == 56, "tap_event layout changed: update internal/observe/tap.go");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} tap_events SEC(".maps");

static __always_inline struct tap_stat *stat_for(__u32 ifindex) {
	struct tap_stat *s = bpf_map_lookup_elem(&tap_stats, &ifindex);
	if (s)
		return s;
	struct tap_stat zero = {};
	bpf_map_update_elem(&tap_stats, &ifindex, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&tap_stats, &ifindex);
}

static __always_inline int may_emit(__u32 ifindex) {
	__u64 now = bpf_ktime_get_ns();
	struct rate *r = bpf_map_lookup_elem(&tap_rate, &ifindex);
	if (!r) {
		struct rate fresh = {.window_ns = now, .count = 0};
		bpf_map_update_elem(&tap_rate, &ifindex, &fresh, BPF_NOEXIST);
		r = bpf_map_lookup_elem(&tap_rate, &ifindex);
		if (!r)
			return 0;
	}
	if (now - r->window_ns >= 1000000000ull) {
		r->window_ns = now;
		r->count = 0;
	}
	return __sync_fetch_and_add(&r->count, 1) < EVENTS_PER_SEC;
}

static __always_inline void emit_connect(__u32 ifindex, __u8 family, __u8 proto, const __u8 *src, const __u8 *dst,
					 __u16 sport, __u16 dport, __u8 dropped) {
	if (!may_emit(ifindex))
		return;
	struct tap_event *e = bpf_ringbuf_reserve(&tap_events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->ifindex = ifindex;
	e->sport = sport;
	e->dport = dport;
	e->family = family;
	e->proto = proto;
	e->dropped = dropped;
	__u32 n = family == FAMILY_INET ? 4 : 16;
	/* Constant-size copies so the verifier can bound them. */
	if (n == 4) {
		__builtin_memcpy(e->src, src, 4);
		__builtin_memcpy(e->dst, dst, 4);
	} else {
		__builtin_memcpy(e->src, src, 16);
		__builtin_memcpy(e->dst, dst, 16);
	}
	bpf_ringbuf_submit(e, 0);
}

/* Multicast and broadcast (mDNS, SSDP, DHCP discovery) are how a LAN talks to itself.
   They are counted, but they do not become events. */
static __always_inline int is_multicast(__u8 family, const __u8 *dst) {
	if (family == FAMILY_INET)
		return dst[0] >= 224; /* 224.0.0.0/4 multicast, and 240/4 with 255.255.255.255 */
	return dst[0] == 0xff;
}

/* True when this UDP flow has not been announced in the last UDP_FLOW_REFRESH_NS. */
static __always_inline int new_udp_flow(__u32 ifindex, __u8 family, const __u8 *src, const __u8 *dst,
					__u16 sport, __u16 dport) {
	struct flow_key k = {.ifindex = ifindex, .sport = sport, .dport = dport, .family = family};
	if (family == FAMILY_INET) {
		__builtin_memcpy(k.src, src, 4);
		__builtin_memcpy(k.dst, dst, 4);
	} else {
		__builtin_memcpy(k.src, src, 16);
		__builtin_memcpy(k.dst, dst, 16);
	}
	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&udp_flows, &k);
	if (last && now - *last < UDP_FLOW_REFRESH_NS)
		return 0;
	bpf_map_update_elem(&udp_flows, &k, &now, BPF_ANY);
	return 1;
}

static __always_inline int allowed4(const __u8 *addr) {
	struct lpm4_key k = {.prefixlen = 32};
	__builtin_memcpy(k.addr, addr, 4);
	return bpf_map_lookup_elem(&allow4, &k) != 0;
}

static __always_inline int allowed6(const __u8 *addr) {
	struct lpm6_key k = {.prefixlen = 128};
	__builtin_memcpy(k.addr, addr, 16);
	return bpf_map_lookup_elem(&allow6, &k) != 0;
}

static __always_inline int handle(struct __sk_buff *skb, int from_guest) {
	/* Not a frame from the guest: the host's own, looped back. Leave it alone. */
	if (from_guest && skb->pkt_type == PACKET_LOOPBACK)
		return TCX_NEXT;

	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return TCX_NEXT;

	__u32 ifindex = skb->ifindex;
	__u16 proto = __builtin_bswap16(eth->h_proto);
	__u32 len = skb->len;

	struct tap_policy *pol = bpf_map_lookup_elem(&tap_policy, &ifindex);
	int isolated = pol && pol->isolated;
	int drop = 0;

	__u8 family = 0;
	const __u8 *src = 0, *dst = 0;
	__u16 sport = 0, dport = 0;
	int syn = 0;
	__u8 l4 = 0;

	if (proto == ETH_P_IP) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > end)
			goto account;
		family = FAMILY_INET;
		src = (const __u8 *)&ip->saddr;
		dst = (const __u8 *)&ip->daddr;
		if (isolated) {
			/* The peer is the destination of what the guest sends and the source of what it
			   receives. Either has to be a management address. */
			drop = !allowed4(from_guest ? dst : src);
		}
		if (ip->protocol == IPPROTO_TCP_ && ip->ihl >= 5) {
			struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
			if ((void *)(tcp + 1) <= end) {
				sport = __builtin_bswap16(tcp->source);
				dport = __builtin_bswap16(tcp->dest);
				syn = tcp->syn && !tcp->ack;
				l4 = IPPROTO_TCP_;
			}
		} else if (ip->protocol == IPPROTO_UDP_ && ip->ihl >= 5) {
			struct udphdr *udp = (void *)ip + ip->ihl * 4;
			if ((void *)(udp + 1) <= end) {
				sport = __builtin_bswap16(udp->source);
				dport = __builtin_bswap16(udp->dest);
				l4 = IPPROTO_UDP_;
			}
		}
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > end)
			goto account;
		family = FAMILY_INET6;
		src = (const __u8 *)&ip6->saddr;
		dst = (const __u8 *)&ip6->daddr;
		if (isolated) {
			int nd = 0;
			if (ip6->nexthdr == IPPROTO_ICMPV6_) {
				/* Neighbour discovery (types 133 to 137) is how the guest finds a
				   gateway. It uses link-local and multicast addresses that no
				   allow list names, so it is always let through. */
				__u8 *icmp = (void *)(ip6 + 1);
				if ((void *)(icmp + 1) <= end && icmp[0] >= 133 && icmp[0] <= 137)
					nd = 1;
			}
			drop = !nd && !allowed6(from_guest ? dst : src);
		}
		if (ip6->nexthdr == IPPROTO_TCP_) {
			struct tcphdr *tcp = (void *)(ip6 + 1);
			if ((void *)(tcp + 1) <= end) {
				sport = __builtin_bswap16(tcp->source);
				dport = __builtin_bswap16(tcp->dest);
				syn = tcp->syn && !tcp->ack;
				l4 = IPPROTO_TCP_;
			}
		} else if (ip6->nexthdr == IPPROTO_UDP_) {
			struct udphdr *udp = (void *)(ip6 + 1);
			if ((void *)(udp + 1) <= end) {
				sport = __builtin_bswap16(udp->source);
				dport = __builtin_bswap16(udp->dest);
				l4 = IPPROTO_UDP_;
			}
		}
	} else if (isolated && proto != ETH_P_ARP) {
		/* ARP is how the guest reaches an allowed address at all. Any other
		   protocol on an isolated VM is dropped. */
		drop = 1;
	}

	if (from_guest && src && dst) {
		if (syn)
			emit_connect(ifindex, family, IPPROTO_TCP_, src, dst, sport, dport, drop);
		else if (l4 == IPPROTO_UDP_ && !is_multicast(family, dst) && new_udp_flow(ifindex, family, src, dst, sport, dport))
			emit_connect(ifindex, family, IPPROTO_UDP_, src, dst, sport, dport, drop);
	}

account:;
	struct tap_stat *s = stat_for(ifindex);
	if (s) {
		if (drop) {
			s->dropped_pkts++;
			s->dropped_bytes += len;
		} else if (from_guest) {
			s->from_pkts++;
			s->from_bytes += len;
		} else {
			s->to_pkts++;
			s->to_bytes += len;
		}
	}
	return drop ? TCX_DROP : TCX_NEXT;
}

SEC("tcx/ingress")
int shukra_tap_from_guest(struct __sk_buff *skb) {
	return handle(skb, 1);
}

SEC("tcx/egress")
int shukra_tap_to_guest(struct __sk_buff *skb) {
	return handle(skb, 0);
}
