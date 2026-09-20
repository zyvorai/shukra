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

/* Set for an ifindex to isolate the VM behind it, and to put it under an egress policy. The value has always
   had seven spare bytes, and egress takes the first, so the map's layout is what it was: a daemon from before
   egress policy writes zeros there, which is "off". */
struct tap_policy {
	__u8 isolated;
	__u8 egress; /* EGRESS_OFF, EGRESS_AUDIT or EGRESS_ENFORCE */
	__u8 pad[6];
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
	__u8 dir;       /* 19: 0 when the guest sent it, 1 when it was sent to the guest (src is then the peer) */
	__u8 policy;    /* 20: 0, or the egress policy's verdict: 1 audit (would have been dropped), 2 dropped */
	__u8 pad[3];    /* 21 */
	__u8 src[16];   /* 24: IPv4 uses the first 4 bytes */
	__u8 dst[16];   /* 40 */
};                      /* 56 */

_Static_assert(sizeof(struct tap_event) == 56, "tap_event layout changed: update internal/observe/tap.go");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} tap_events SEC(".maps");

/* Guest DNS queries. The program only recognises a plain query (QR=0, OPCODE=0, one question) and hands the
   question section to userspace as raw wire bytes; the name is decoded there, where it can be tested and
   cannot upset the verifier. A repeat of the same name and type on the same tap is announced once a minute,
   and queries are rate-limited per tap on their own, so a resolver storm cannot starve the connect events.
   dns_cfg[0] is 1 when the operator turned name events off (shukrad -dns-events=false): the program then
   does not look at DNS at all. An array starts as zero, so "on" is the default. */
#define DNS_RAW 128
#define DNS_REFRESH_NS 60000000000ull
#define DNS_PER_SEC 200

struct dns_event {
	__u64 ts_ns;      /* 0 */
	__u32 ifindex;    /* 8 */
	__u8 family;      /* 12 */
	__u8 flags;       /* 13: 1 when isolation dropped this query, 2 when the name did not end inside raw */
	__u16 rawlen;     /* 14: how many bytes of raw are the packet's */
	__u8 src[16];     /* 16 */
	__u8 dst[16];     /* 32 */
	__u8 raw[DNS_RAW]; /* 48: the question section, wire format */
};                        /* 176 */

_Static_assert(sizeof(struct dns_event) == 176, "dns_event layout changed: update internal/observe/dns.go");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} tap_dns SEC(".maps");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dns_cfg SEC(".maps");

struct dns_seen_key {
	__u32 ifindex;
	__u32 pad;
	__u64 hash;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct dns_seen_key);
	__type(value, __u64);
} dns_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct rate);
} dns_rate SEC(".maps");

/* Guest TLS ClientHellos. A guest TCP segment whose payload starts with a TLS handshake record (0x16, major
   version 3) carrying a ClientHello (handshake type 1) is copied, up to TLS_RAW bytes (a whole first segment on an
   Ethernet MTU), to userspace as raw
   wire bytes: the server name, the ALPN list and the fingerprint are decoded there, where it can be tested
   and cannot upset the verifier. Only the first segment of a hello is seen, so one that is longer than the
   copy or is split over segments arrives cut short, and says so. A flow is announced once (a retransmitted
   hello is not a second event), and hellos are rate-limited per tap on their own budget.
   tls_cfg[0] is 1 when the operator turned TLS events off (shukrad -tls-events=false): the program then
   does not read a TCP payload at all. An array starts as zero, so "on" is the default. */
#define TLS_RAW 1504
#define TLS_PEEK 7
#define TLS_FLOW_REFRESH_NS 30000000000ull
#define TLS_PER_SEC 100

struct tls_event {
	__u64 ts_ns;       /* 0 */
	__u32 ifindex;     /* 8 */
	__u8 family;       /* 12 */
	__u8 flags;        /* 13: 1 when isolation dropped this segment */
	__u16 rawlen;      /* 14: how many bytes of raw are the packet's */
	__u16 sport;       /* 16 */
	__u16 dport;       /* 18 */
	__u8 pad[4];       /* 20 */
	__u8 src[16];      /* 24 */
	__u8 dst[16];      /* 40 */
	__u8 raw[TLS_RAW]; /* 56: the TCP payload, from the record header */
};                         /* 1560 */

_Static_assert(sizeof(struct tls_event) == 1560, "tls_event layout changed: update internal/observe/tls.go");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} tap_tls SEC(".maps");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tls_cfg SEC(".maps");

/* Hellos announced recently. The key is made of values the guest controls, so it is an LRU of a fixed size
   and not pinned. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, __u64);
} tls_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct rate);
} tls_rate SEC(".maps");

/* Egress policy. A VM whose tap_policy.egress is not off may start a TCP connection or send a UDP datagram only
   to a network that is on its own allow list (egress4 and egress6), or on the management allow list, which no
   policy can take away. In audit mode nothing is dropped: what would have been is counted, and reported on the
   connect event. In enforce mode it is dropped, as isolation drops.

   It judges new things only: a TCP SYN (so an established connection, and a server's answers, are never
   touched, since they can only exist where the SYN was let through or came in) and a UDP datagram that is not
   multicast and is not a reply (a datagram to a peer that sent one to the guest in the last minute).
   ICMP, ARP and everything else are not judged.

   The keys carry the ifindex, so one trie holds every VM's list: prefixlen is 32 (the ifindex, matched
   exactly) plus the length of the network. */
#define EGRESS_OFF 0
#define EGRESS_AUDIT 1
#define EGRESS_ENFORCE 2
#define EGRESS_UDP_REPLY_NS 60000000000ull

struct egress4_key {
	__u32 prefixlen;
	__u32 ifindex;
	__u8 addr[4];
};

struct egress6_key {
	__u32 prefixlen;
	__u32 ifindex;
	__u8 addr[16];
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct egress4_key);
	__type(value, __u8);
} egress4 SEC(".maps");

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct egress6_key);
	__type(value, __u8);
} egress6 SEC(".maps");

/* What the policy did, per tap and per CPU. checked is every new connection or datagram it judged. */
struct egress_stat {
	__u64 checked;
	__u64 audit_pkts;
	__u64 audit_bytes;
	__u64 drop_pkts;
	__u64 drop_bytes;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* ifindex */
	__type(value, struct egress_stat);
} egress_stats SEC(".maps");

/* UDP flows that a peer started, so the guest's answers to them are not judged. The key is what the guest's
   answer looks like (guest as source), and the map is an LRU of a fixed size that is not pinned: the guest
   cannot grow it and a restart does not inherit it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, __u64);
} egress_udp_in SEC(".maps");

/* TCP handshake outcomes. A SYN is remembered until it is answered: a SYN-ACK means the connection was
   accepted, an RST means it was refused, and one that is never answered is counted as a timeout by
   userspace (BPF has no timers), which sweeps the pending table. dir says who started it. */
#define DIR_OUT 0 /* the guest sent the SYN */
#define DIR_IN 1  /* the SYN was sent to the guest */

struct tap_outcome {
	__u64 out_syn;
	__u64 out_ok;
	__u64 out_refused;
	__u64 out_retrans;
	__u64 out_blocked; /* a SYN isolation dropped: not pending, so never a timeout */
	__u64 in_syn;
	__u64 in_ok;
	__u64 in_refused;
	__u64 in_retrans;
	__u64 in_blocked;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); /* ifindex */
	__type(value, struct tap_outcome);
} tap_outcomes SEC(".maps");

/* How long an outbound connection took to be answered, as a log2 histogram of nanoseconds. */
struct hs_key {
	__u32 ifindex;
	__u32 bucket;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct hs_key);
	__type(value, __u64);
} tap_handshake_hist SEC(".maps");

/* Written only by userspace: SYNs that were never answered. A separate map, because a userspace
   read-modify-write of a per-CPU value would race with this program's own increments. */
struct tap_timeout {
	__u64 out_timeout;
	__u64 in_ignored;
};

struct {
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct tap_timeout);
} tap_timeouts SEC(".maps");

/* SYNs waiting for an answer. The key is made of values the guest controls, so it is an LRU of a fixed
   size, and not pinned: a restart must not inherit handshakes that were in flight. Explicit padding, so
   two keys for the same flow are byte-for-byte equal. Mirrored by internal/bpfgen/tap.go. */
struct pend_key {
	__u32 ifindex;
	__u16 gport; /* the guest's port */
	__u16 pport; /* the peer's port */
	__u8 family;
	__u8 dir;
	__u8 pad[2];
	__u8 g[16]; /* the guest's address */
	__u8 p[16]; /* the peer's address */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct pend_key);
	__type(value, __u64); /* bpf_ktime_get_ns of the SYN */
} pending_syn SEC(".maps");

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
					 __u16 sport, __u16 dport, __u8 dropped, __u8 dir, __u8 policy) {
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
	e->dir = dir;
	e->policy = policy;
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

static __always_inline int egress_in4(__u32 ifindex, const __u8 *addr) {
	struct egress4_key k = {.prefixlen = 64, .ifindex = ifindex};
	__builtin_memcpy(k.addr, addr, 4);
	return bpf_map_lookup_elem(&egress4, &k) != 0;
}

static __always_inline int egress_in6(__u32 ifindex, const __u8 *addr) {
	struct egress6_key k = {.prefixlen = 160, .ifindex = ifindex};
	__builtin_memcpy(k.addr, addr, 16);
	return bpf_map_lookup_elem(&egress6, &k) != 0;
}

static __always_inline struct egress_stat *egress_stat_for(__u32 ifindex) {
	struct egress_stat *s = bpf_map_lookup_elem(&egress_stats, &ifindex);
	if (s)
		return s;
	struct egress_stat zero = {};
	bpf_map_update_elem(&egress_stats, &ifindex, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&egress_stats, &ifindex);
}

/* The flow key of a UDP datagram as the guest sends it: the guest is the source. */
static __always_inline void udp_key(struct flow_key *k, __u32 ifindex, __u8 family, const __u8 *src, const __u8 *dst,
				    __u16 sport, __u16 dport) {
	k->ifindex = ifindex;
	k->sport = sport;
	k->dport = dport;
	k->family = family;
	if (family == FAMILY_INET) {
		__builtin_memcpy(k->src, src, 4);
		__builtin_memcpy(k->dst, dst, 4);
	} else {
		__builtin_memcpy(k->src, src, 16);
		__builtin_memcpy(k->dst, dst, 16);
	}
}

/* A UDP datagram sent TO the guest: remember that the guest may answer it. src is the peer, dst the guest. The
   key is the answer's, so it is written with the guest as the source, and only when it is new or old enough to
   need a refresh. */
static __always_inline void egress_udp_seen(__u32 ifindex, __u8 family, const __u8 *src, const __u8 *dst, __u16 sport,
					    __u16 dport) {
	struct flow_key k = {};
	udp_key(&k, ifindex, family, dst, src, dport, sport);
	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&egress_udp_in, &k);
	if (last && now - *last < EGRESS_UDP_REPLY_NS / 12)
		return;
	bpf_map_update_elem(&egress_udp_in, &k, &now, BPF_ANY);
}

/* The verdict on a new TCP connection or UDP datagram from a guest whose tap has an egress policy: 0 to let it
   through, 1 in audit mode when it is outside the policy, 2 in enforce mode when it is. */
static __always_inline int egress_check(__u32 ifindex, __u8 family, const __u8 *src, const __u8 *dst, __u16 sport,
					__u16 dport, __u8 l4, __u8 mode, __u32 len) {
	struct egress_stat *st = egress_stat_for(ifindex);
	if (st)
		st->checked++;
	int inside;
	if (family == FAMILY_INET)
		inside = allowed4(dst) || egress_in4(ifindex, dst);
	else
		inside = allowed6(dst) || egress_in6(ifindex, dst);
	if (!inside && l4 == IPPROTO_UDP_) {
		struct flow_key k = {};
		udp_key(&k, ifindex, family, src, dst, sport, dport);
		__u64 *last = bpf_map_lookup_elem(&egress_udp_in, &k);
		inside = last && bpf_ktime_get_ns() - *last < EGRESS_UDP_REPLY_NS;
	}
	if (inside)
		return 0;
	if (mode == EGRESS_ENFORCE) {
		if (st) {
			st->drop_pkts++;
			st->drop_bytes += len;
		}
		return 2;
	}
	if (st) {
		st->audit_pkts++;
		st->audit_bytes += len;
	}
	return 1;
}

static __always_inline struct tap_outcome *outcome_for(__u32 ifindex) {
	struct tap_outcome *o = bpf_map_lookup_elem(&tap_outcomes, &ifindex);
	if (o)
		return o;
	struct tap_outcome zero = {};
	bpf_map_update_elem(&tap_outcomes, &ifindex, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&tap_outcomes, &ifindex);
}

/* Slot for a latency in ns: bits.Len64(v)-1. Mirrors internal/hist.Bucket and log2_bucket in event.h. */
static __always_inline __u32 hs_bucket(__u64 v) {
	__u32 r = 0;
	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

static __always_inline void hs_observe(__u32 ifindex, __u64 ns) {
	struct hs_key k = {.ifindex = ifindex, .bucket = hs_bucket(ns)};
	__u64 *c = bpf_map_lookup_elem(&tap_handshake_hist, &k);
	if (c) {
		(*c)++;
		return;
	}
	__u64 one = 1;
	bpf_map_update_elem(&tap_handshake_hist, &k, &one, BPF_NOEXIST);
}

/* Follows one TCP handshake packet. A SYN is remembered; a SYN-ACK or RST that answers a remembered SYN
   is counted and forgets it. Returns 1 for a SYN sent TO the guest, which is the one that becomes an
   event: a retransmit of the same SYN is counted, but is not announced again. */
static __always_inline int track_handshake(__u32 ifindex, int from_guest, __u8 family, const __u8 *src, const __u8 *dst,
					   __u16 sport, __u16 dport, int syn, int synack, int drop) {
	struct tap_outcome *o = outcome_for(ifindex);
	if (!o)
		return 0;
	struct pend_key k = {.ifindex = ifindex, .family = family};
	const __u8 *guest = from_guest ? src : dst;
	const __u8 *peer = from_guest ? dst : src;
	k.gport = from_guest ? sport : dport;
	k.pport = from_guest ? dport : sport;
	if (family == FAMILY_INET) {
		__builtin_memcpy(k.g, guest, 4);
		__builtin_memcpy(k.p, peer, 4);
	} else {
		__builtin_memcpy(k.g, guest, 16);
		__builtin_memcpy(k.p, peer, 16);
	}

	if (syn) {
		k.dir = from_guest ? DIR_OUT : DIR_IN;
		if (drop) { /* isolation dropped it: an attempt that will never be answered, so it is not left pending */
			if (from_guest) {
				o->out_syn++;
				o->out_blocked++;
			} else {
				o->in_syn++;
				o->in_blocked++;
			}
			return !from_guest;
		}
		if (bpf_map_lookup_elem(&pending_syn, &k)) {
			/* The same SYN again: counted as a retransmit, not as a new attempt. */
			if (from_guest)
				o->out_retrans++;
			else
				o->in_retrans++;
			return 0;
		}
		if (from_guest)
			o->out_syn++;
		else
			o->in_syn++;
		__u64 now = bpf_ktime_get_ns();
		bpf_map_update_elem(&pending_syn, &k, &now, BPF_NOEXIST);
		return !from_guest;
	}

	/* An answer: the guest's SYN-ACK or RST answers a SYN sent to it, and the peer's answers the guest's. */
	k.dir = from_guest ? DIR_IN : DIR_OUT;
	__u64 *ts = bpf_map_lookup_elem(&pending_syn, &k);
	if (!ts)
		return 0;
	__u64 t0 = *ts;
	bpf_map_delete_elem(&pending_syn, &k);
	if (k.dir == DIR_OUT) {
		if (synack) {
			o->out_ok++;
			hs_observe(ifindex, bpf_ktime_get_ns() - t0);
		} else {
			o->out_refused++;
		}
	} else if (synack) {
		o->in_ok++;
	} else {
		o->in_refused++;
	}
	return 0;
}

static __always_inline int dns_may_emit(__u32 ifindex) {
	__u64 now = bpf_ktime_get_ns();
	struct rate *r = bpf_map_lookup_elem(&dns_rate, &ifindex);
	if (!r) {
		struct rate fresh = {.window_ns = now, .count = 0};
		bpf_map_update_elem(&dns_rate, &ifindex, &fresh, BPF_NOEXIST);
		r = bpf_map_lookup_elem(&dns_rate, &ifindex);
		if (!r)
			return 0;
	}
	if (now - r->window_ns >= 1000000000ull) {
		r->window_ns = now;
		r->count = 0;
	}
	return __sync_fetch_and_add(&r->count, 1) < DNS_PER_SEC;
}

/* A DNS query the guest sent to UDP port 53. off is where the UDP payload starts. */
static __always_inline void dns_query(struct __sk_buff *skb, __u32 ifindex, __u8 family, const __u8 *src,
				      const __u8 *dst, __u32 off, __u8 dropped) {
	__u32 zero = 0;
	__u32 *off_flag = bpf_map_lookup_elem(&dns_cfg, &zero);
	if (off_flag && *off_flag)
		return;

	__u8 hdr[12] = {};
	if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0)
		return;
	/* QR=0 (a query), OPCODE=0 (standard), and exactly one question. Anything else is not a name lookup. */
	if ((hdr[2] & 0xF8) != 0 || hdr[4] != 0 || hdr[5] != 1)
		return;

	__u64 plen = skb->len, start = off + 12;
	if (plen <= start)
		return;
	__u64 have = plen - start;
	/* The verifier must be able to prove 1 <= have <= DNS_RAW. A comparison against zero is not enough for it
	   (it keeps the lower bound only for a 32-bit view), so the bound is built by arithmetic: m is 0 to
	   DNS_RAW - 1 and have is m + 1. */
	__u64 m = have - 1;
	if (m > DNS_RAW - 1)
		m = DNS_RAW - 1;
	have = m + 1;

	__u8 raw[DNS_RAW] = {};
	if (bpf_skb_load_bytes(skb, off + 12, raw, have) < 0)
		return;

	/* Walk the name, to hash it (case-folded, with the type) and to know where it ends. A length byte above
	   63 is a compression pointer or an extension, neither of which a plain first question has. */
	__u64 h = 1469598103934665603ull ^ ifindex;
	__u32 stage = 0, left = 0, tail = 0;
	int done = 0, bad = 0;
	for (int i = 0; i < DNS_RAW; i++) {
		if (i >= have)
			break;
		__u8 c = raw[i];
		if (stage == 0) {
			if (c == 0) {
				stage = 2;
			} else if (c > 63) {
				bad = 1;
				break;
			} else {
				left = c;
				stage = 1;
			}
			h = (h ^ c) * 1099511628211ull;
		} else if (stage == 1) {
			if (c >= 'A' && c <= 'Z')
				c += 32;
			h = (h ^ c) * 1099511628211ull;
			if (--left == 0)
				stage = 0;
		} else {
			if (tail < 2)
				h = (h ^ c) * 1099511628211ull;
			if (++tail >= 4) {
				done = 1;
				break;
			}
		}
	}
	if (bad)
		return;

	__u64 now = bpf_ktime_get_ns();
	struct dns_seen_key k = {.ifindex = ifindex, .hash = h};
	__u64 *last = bpf_map_lookup_elem(&dns_seen, &k);
	if (last && now - *last < DNS_REFRESH_NS)
		return;
	if (!dns_may_emit(ifindex))
		return;
	bpf_map_update_elem(&dns_seen, &k, &now, BPF_ANY);

	struct dns_event *e = bpf_ringbuf_reserve(&tap_dns, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = now;
	e->ifindex = ifindex;
	e->family = family;
	e->flags = (dropped ? 1 : 0) | (done ? 0 : 2);
	e->rawlen = (__u16)have;
	if (family == FAMILY_INET) {
		__builtin_memcpy(e->src, src, 4);
		__builtin_memcpy(e->dst, dst, 4);
	} else {
		__builtin_memcpy(e->src, src, 16);
		__builtin_memcpy(e->dst, dst, 16);
	}
	__builtin_memcpy(e->raw, raw, DNS_RAW);
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int tls_may_emit(__u32 ifindex) {
	__u64 now = bpf_ktime_get_ns();
	struct rate *r = bpf_map_lookup_elem(&tls_rate, &ifindex);
	if (!r) {
		struct rate fresh = {.window_ns = now, .count = 0};
		bpf_map_update_elem(&tls_rate, &ifindex, &fresh, BPF_NOEXIST);
		r = bpf_map_lookup_elem(&tls_rate, &ifindex);
		if (!r)
			return 0;
	}
	if (now - r->window_ns >= 1000000000ull) {
		r->window_ns = now;
		r->count = 0;
	}
	return __sync_fetch_and_add(&r->count, 1) < TLS_PER_SEC;
}

/* A TCP segment the guest sent. off is where its payload starts. It is a ClientHello when the payload begins
   with a handshake record (0x16, version 3.x) whose first handshake message is of type 1. */
static __always_inline void tls_hello(struct __sk_buff *skb, __u32 ifindex, __u8 family, const __u8 *src,
				      const __u8 *dst, __u16 sport, __u16 dport, __u32 off, __u8 dropped) {
	__u32 zero = 0;
	__u32 *off_flag = bpf_map_lookup_elem(&tls_cfg, &zero);
	if (off_flag && *off_flag)
		return;

	/* A record header (5 bytes), the handshake type and the top byte of its 24-bit length. Encrypted data is
	   random, so every byte that is checked makes it less likely that a segment of it is taken for a hello: a
	   record version of 3.0 to 3.4, and a hello shorter than 64 KiB. */
	__u8 hdr[TLS_PEEK] = {};
	if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0)
		return;
	if (hdr[0] != 0x16 || hdr[1] != 3 || hdr[2] > 4 || hdr[5] != 1 || hdr[6] != 0)
		return;

	struct flow_key k = {.ifindex = ifindex, .sport = sport, .dport = dport, .family = family};
	if (family == FAMILY_INET) {
		__builtin_memcpy(k.src, src, 4);
		__builtin_memcpy(k.dst, dst, 4);
	} else {
		__builtin_memcpy(k.src, src, 16);
		__builtin_memcpy(k.dst, dst, 16);
	}
	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&tls_flows, &k);
	if (last && now - *last < TLS_FLOW_REFRESH_NS)
		return;
	if (!tls_may_emit(ifindex))
		return;
	bpf_map_update_elem(&tls_flows, &k, &now, BPF_ANY);

	struct tls_event *e = bpf_ringbuf_reserve(&tap_tls, sizeof(*e), 0);
	if (!e)
		return;
	/* Only the header is cleared: raw is 1.5 KB, and only rawlen bytes of it are ever read. */
	__builtin_memset(e, 0, __builtin_offsetof(struct tls_event, raw));

	/* The verifier must be able to prove 1 <= have <= TLS_RAW. As for a DNS question, the bound is built by
	   arithmetic on 64-bit values: m is 0 to TLS_RAW - 1 and have is m + 1. */
	__u64 plen = skb->len, start = off;
	__u64 m = plen - start - 1;
	if (plen <= start || m > TLS_RAW - 1)
		m = TLS_RAW - 1;
	__u64 have = m + 1;
	if (bpf_skb_load_bytes(skb, off, e->raw, have) < 0) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	e->ts_ns = now;
	e->ifindex = ifindex;
	e->family = family;
	e->flags = dropped ? 1 : 0;
	e->rawlen = (__u16)have;
	e->sport = sport;
	e->dport = dport;
	if (family == FAMILY_INET) {
		__builtin_memcpy(e->src, src, 4);
		__builtin_memcpy(e->dst, dst, 4);
	} else {
		__builtin_memcpy(e->src, src, 16);
		__builtin_memcpy(e->dst, dst, 16);
	}
	bpf_ringbuf_submit(e, 0);
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
	__u8 egress = pol ? pol->egress : EGRESS_OFF;
	__u8 verdict = 0; /* the egress policy's, for the connect event */
	int drop = 0;

	__u8 family = 0;
	const __u8 *src = 0, *dst = 0;
	__u16 sport = 0, dport = 0;
	int syn = 0, synack = 0, rst = 0;
	__u8 l4 = 0;
	__u32 l4off = 0;  /* where a UDP payload starts */
	__u32 tlsoff = 0; /* where a TCP payload starts */

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
				synack = tcp->syn && tcp->ack;
				rst = tcp->rst;
				l4 = IPPROTO_TCP_;
				if (tcp->doff >= 5)
					tlsoff = sizeof(*eth) + ip->ihl * 4 + tcp->doff * 4;
			}
		} else if (ip->protocol == IPPROTO_UDP_ && ip->ihl >= 5) {
			struct udphdr *udp = (void *)ip + ip->ihl * 4;
			if ((void *)(udp + 1) <= end) {
				sport = __builtin_bswap16(udp->source);
				dport = __builtin_bswap16(udp->dest);
				l4 = IPPROTO_UDP_;
				l4off = sizeof(*eth) + ip->ihl * 4 + sizeof(*udp);
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
				synack = tcp->syn && tcp->ack;
				rst = tcp->rst;
				l4 = IPPROTO_TCP_;
				if (tcp->doff >= 5)
					tlsoff = sizeof(*eth) + sizeof(*ip6) + tcp->doff * 4;
			}
		} else if (ip6->nexthdr == IPPROTO_UDP_) {
			struct udphdr *udp = (void *)(ip6 + 1);
			if ((void *)(udp + 1) <= end) {
				sport = __builtin_bswap16(udp->source);
				dport = __builtin_bswap16(udp->dest);
				l4 = IPPROTO_UDP_;
				l4off = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp);
			}
		}
	} else if (isolated && proto != ETH_P_ARP) {
		/* ARP is how the guest reaches an allowed address at all. Any other
		   protocol on an isolated VM is dropped. */
		drop = 1;
	}

	/* The egress policy, when this tap has one. What a peer sends is only remembered (UDP, so that the guest's
	   answers are not judged); what the guest sends is judged if it is new: a SYN, or a datagram that is neither
	   multicast nor an answer. It comes before the handshake is followed, so that a connection the policy
	   dropped is counted as blocked, as one isolation dropped is. An isolated tap is already dropping all. */
	if (egress != EGRESS_OFF && src && dst) {
		if (!from_guest) {
			if (l4 == IPPROTO_UDP_)
				egress_udp_seen(ifindex, family, src, dst, sport, dport);
		} else if (!drop && ((l4 == IPPROTO_TCP_ && syn) || (l4 == IPPROTO_UDP_ && !is_multicast(family, dst)))) {
			verdict = egress_check(ifindex, family, src, dst, sport, dport, l4, egress, len);
			if (verdict == 2)
				drop = 1;
		}
	}

	/* Follow the TCP handshake: what was answered, refused, or is still waiting, either way round. */
	int inbound_new = 0;
	if (l4 == IPPROTO_TCP_ && src && dst && (syn || synack || rst))
		inbound_new = track_handshake(ifindex, from_guest, family, src, dst, sport, dport, syn, synack, drop);

	if (from_guest && src && dst) {
		if (syn)
			emit_connect(ifindex, family, IPPROTO_TCP_, src, dst, sport, dport, drop, DIR_OUT, verdict);
		else if (l4 == IPPROTO_UDP_ && !is_multicast(family, dst) && new_udp_flow(ifindex, family, src, dst, sport, dport))
			emit_connect(ifindex, family, IPPROTO_UDP_, src, dst, sport, dport, drop, DIR_OUT, verdict);
		if (l4 == IPPROTO_UDP_ && dport == 53 && l4off)
			dns_query(skb, ifindex, family, src, dst, l4off, drop);
		/* A TCP segment that carries data: its payload may be the start of a ClientHello. */
		if (l4 == IPPROTO_TCP_ && tlsoff && !syn && !synack && !rst && skb->len >= tlsoff + TLS_PEEK)
			tls_hello(skb, ifindex, family, src, dst, sport, dport, tlsoff, drop);
	} else if (inbound_new) {
		/* Someone connecting INTO the guest. src is the peer, dst is the guest. */
		emit_connect(ifindex, family, IPPROTO_TCP_, src, dst, sport, dport, drop, DIR_IN, 0);
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
