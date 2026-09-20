#!/usr/bin/env bash
# test-tap-progrun.sh [OBJECT]: the tap program's egress policy, tried packet by packet on a real kernel.
#
# The program is loaded as a private copy (its own maps, in a mount namespace with a fresh bpffs, attached to
# nothing) and run on hand-built packets with BPF_PROG_TEST_RUN, so what is checked is the verdict the kernel
# program itself gives: TCX_NEXT (let it through) or TCX_DROP. It needs no namespace, veth or VM and touches
# nothing a running shukrad has pinned, so it is safe anywhere with root, bpftool and python3. The end-to-end
# behaviour (a real guest, the daemon, restarts) is scripts/test-tap.sh.
#
# OBJECT defaults to the CO-RE object `make generate` writes to internal/bpfgen.
set -euo pipefail
[ "$(id -u)" = 0 ] || exec sudo -E "$0" "$@"
HERE="$(cd "$(dirname "$0")" && pwd)"
OBJ="${1:-$(ls "$HERE"/../internal/bpfgen/tap_*_bpfel.o 2>/dev/null | head -1)}"
[ -r "$OBJ" ] || { echo "no tap object: pass one, or run make generate"; exit 2; }
OBJ="$(cd "$(dirname "$OBJ")" && pwd)/$(basename "$OBJ")"
if [ "${1:-}" != "--inner" ] && [ -z "${SHUKRA_PROGRUN_INNER:-}" ]; then
  export SHUKRA_PROGRUN_INNER=1
  exec unshare -m bash "$0" "$OBJ"
fi
mount --make-rprivate / 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf
exec python3 - "$OBJ" <<'PY'
import json, struct, subprocess, sys, tempfile, os

OBJ = sys.argv[1]
PASS = FAIL = 0
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("%s: %s" % (" ".join(a), r.stderr.strip()))
    return r.stdout
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok: PASS += 1; print("  PASS ", name)
    else:  FAIL += 1; print("  FAIL ", name, detail)

run("bpftool", "prog", "loadall", OBJ, "/sys/fs/bpf/p")
FROM, TO = "/sys/fs/bpf/p/shukra_tap_from_guest", "/sys/fs/bpf/p/shukra_tap_to_guest"
IF = 1  # BPF_PROG_TEST_RUN runs on the loopback device, so ifindex 1

# --- packets
D = tempfile.mkdtemp()
GUEST, MGMT, IN_LIST, OUTSIDE, PEER = "10.0.0.5", "10.99.0.1", "203.0.113.9", "198.51.100.7", "192.0.2.44"
def eth(t): return bytes([2,0,0,0,0,1, 2,0,0,0,0,2]) + struct.pack(">H", t)
def ip4(proto, src, dst, n):
    a = lambda s: bytes(int(x) for x in s.split("."))
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + n, 1, 0x4000, 64, proto, 0, a(src), a(dst))
def tcp(sport, dport, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, flags, 65535, 0, 0) + payload
def udp(sport, dport, n=20):
    return struct.pack(">HHHH", sport, dport, 8 + n, 0) + bytes(n)
def v4(proto, src, dst, l4): return eth(0x0800) + ip4(proto, src, dst, len(l4)) + l4
import ipaddress
def v6(proto, src, dst, l4):
    h = struct.pack(">IHBB", 6 << 28, len(l4), proto, 64) + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return eth(0x86dd) + h + l4
SYN, SYNACK, ACK, PSH = 0x02, 0x12, 0x10, 0x18
pk = {
  "syn_in_list":   v4(6, GUEST, IN_LIST, tcp(40000, 443, SYN)),
  "syn_outside":   v4(6, GUEST, OUTSIDE, tcp(40000, 443, SYN)),
  "syn_mgmt":      v4(6, GUEST, MGMT, tcp(40000, 22, SYN)),
  "ack_outside":   v4(6, GUEST, OUTSIDE, tcp(40000, 443, PSH, b"x" * 100)),
  "synack_outside":v4(6, GUEST, OUTSIDE, tcp(8080, 50000, SYNACK)),
  "udp_outside":   v4(17, GUEST, OUTSIDE, udp(40001, 5300)),
  "udp_in_list":   v4(17, GUEST, IN_LIST, udp(40001, 5300)),
  "udp_multicast": v4(17, GUEST, "224.0.0.251", udp(5353, 5353)),
  "udp_broadcast": v4(17, GUEST, "255.255.255.255", udp(68, 67)),
  "icmp_outside":  v4(1, GUEST, OUTSIDE, bytes([8, 0, 0, 0, 0, 1, 0, 1])),
  "udp_from_peer": v4(17, PEER, GUEST, udp(5000, 4000)),          # sent TO the guest
  "udp_reply":     v4(17, GUEST, PEER, udp(4000, 5000)),          # the guest's answer
  "udp_other_port":v4(17, GUEST, PEER, udp(4000, 5001)),          # not an answer to that flow
  "udp_other_peer":v4(17, GUEST, OUTSIDE, udp(4000, 5000)),
  "syn6_in_list":  v6(6, "fd00::5", "2001:db8::9", tcp(40000, 443, SYN)),
  "syn6_outside":  v6(6, "fd00::5", "2001:db9::9", tcp(40000, 443, SYN)),
  "syn6_mgmt":     v6(6, "fd00::5", "fd99::1", tcp(40000, 22, SYN)),
  "syn6_host":     v6(6, "fd00::5", "2001:db9:1::5", tcp(40000, 443, SYN)),
  "syn6_neighbour":v6(6, "fd00::5", "2001:db9:1::6", tcp(40000, 443, SYN)),
  "udp6_multicast":v6(17, "fd00::5", "ff02::fb", udp(5353, 5353)),
}
for k, v in pk.items(): open("%s/%s" % (D, k), "wb").write(v)

def verdict(name, prog=FROM):
    out = run("bpftool", "prog", "run", "pinned", prog, "data_in", "%s/%s" % (D, name), "repeat", "1")
    v = int(out.split("Return value:")[1].split(",")[0])
    return {4294967295: "next", 2: "drop"}.get(v, str(v))

# --- maps, by hand
def bs(*b): return " ".join(str(x) for x in b)
def u32(n): return struct.pack("<I", n)
def hx(b): return ["%02x" % x for x in b]
def put(m, key, value): run("bpftool", "map", "update", "pinned", "/sys/fs/bpf/" + m, "key", "hex", *hx(key), "value", "hex", *hx(value))
def mode(m, isolated=0): put("tap_policy", u32(IF), bytes([isolated, m]) + bytes(6))
def allow4(prefix, bits, ifindex=IF):
    put("egress4", u32(32 + bits) + u32(ifindex) + bytes(int(x) for x in prefix.split(".")), b"\x01")
def allow6(prefix, bits, ifindex=IF):
    put("egress6", u32(32 + bits) + u32(ifindex) + ipaddress.IPv6Address(prefix).packed, b"\x01")
def stats():
    j = json.loads(run("bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/egress_stats"))
    tot = [0] * 5
    for e in j:
        for c in e["values"]:
            v = c.get("formatted", None)
            if v is not None:
                vals = [v[k] for k in ("checked", "audit_pkts", "audit_bytes", "drop_pkts", "drop_bytes")]
            else:
                b = bytes(int(x, 16) for x in c["value"]); vals = struct.unpack_from("<5Q", b)
            tot = [a + b for a, b in zip(tot, vals)]
    return dict(zip(("checked", "audit", "audit_bytes", "drop", "drop_bytes"), tot))

# the management allow list: 10.99.0.1/32 and fd99::1/128 (allow4 and allow6 are the isolation floor)
put("allow4", u32(32) + bytes([10, 99, 0, 1]), b"\x01")
put("allow6", u32(128) + ipaddress.IPv6Address("fd99::1").packed, b"\x01")
allow4(IN_LIST, 24)
allow6("2001:db8::", 32)

print("== egress policy off: nothing is judged")
mode(0)
for n in ("syn_outside", "udp_outside", "syn6_outside"):
    check("%s passes" % n, verdict(n) == "next")
check("and nothing was counted", stats() == {"checked": 0, "audit": 0, "audit_bytes": 0, "drop": 0, "drop_bytes": 0})

print("== audit: everything passes, and what would have been dropped is counted")
mode(1)
check("a SYN to a listed network passes", verdict("syn_in_list") == "next")
check("a SYN outside passes in audit mode", verdict("syn_outside") == "next")
check("a UDP datagram outside passes in audit mode", verdict("udp_outside") == "next")
check("an IPv6 SYN outside passes in audit mode", verdict("syn6_outside") == "next")
s = stats()
check("four things were judged and three would have been dropped, none was", s["checked"] == 4 and s["audit"] == 3 and s["drop"] == 0, s)
check("the audit bytes are those of the packets", s["audit_bytes"] == len(pk["syn_outside"]) + len(pk["udp_outside"]) + len(pk["syn6_outside"]), s)

print("== enforce: outside the list is dropped, and only what is new")
run("bpftool", "map", "delete", "pinned", "/sys/fs/bpf/egress_stats", "key", "hex", *hx(u32(IF)))
mode(2)
check("a SYN to a listed network passes", verdict("syn_in_list") == "next")
check("a SYN outside is dropped", verdict("syn_outside") == "drop")
check("a UDP datagram outside is dropped", verdict("udp_outside") == "drop")
check("a UDP datagram to a listed network passes", verdict("udp_in_list") == "next")
check("a SYN to the management network passes although it is not on the list: no policy can cut it", verdict("syn_mgmt") == "next")
check("data on a connection (not a SYN) passes wherever it goes: only new connections are judged", verdict("ack_outside") == "next")
check("a SYN-ACK passes: a server answering a connection that came in", verdict("synack_outside") == "next")
check("ICMP is not judged", verdict("icmp_outside") == "next")
check("multicast (mDNS) is not judged", verdict("udp_multicast") == "next")
check("broadcast (DHCP discovery) is not judged", verdict("udp_broadcast") == "next")
check("IPv6: a listed network passes", verdict("syn6_in_list") == "next")
check("IPv6: outside is dropped", verdict("syn6_outside") == "drop")
check("IPv6: the management network passes", verdict("syn6_mgmt") == "next")
check("IPv6 multicast is not judged", verdict("udp6_multicast") == "next")
s = stats()
check("the counters say so: three dropped, and they are the packets' bytes", s["drop"] == 3 and s["drop_bytes"] == len(pk["syn_outside"]) + len(pk["udp_outside"]) + len(pk["syn6_outside"]) and s["audit"] == 0, s)

print("== UDP answers: a guest that serves UDP can reply to whoever asked")
check("an answer with nothing before it is dropped", verdict("udp_reply") == "drop")
check("the datagram to the guest is not judged", verdict("udp_from_peer", TO) == "next")
check("and now the guest's answer passes", verdict("udp_reply") == "next")
check("an answer from another port is not the answer", verdict("udp_other_port") == "drop")
check("nor is one to another peer", verdict("udp_other_peer") == "drop")

print("== the list belongs to one tap")
allow4(OUTSIDE, 24, ifindex=2)
check("a network another tap may reach is still outside for this one", verdict("syn_outside") == "drop")
allow4(OUTSIDE, 32)
check("a /32 on this tap's own list lets it through", verdict("syn_outside") == "next")
put("egress4", u32(32) + u32(IF) + bytes(4), b"\x01")
check("a /0 allows every IPv4 destination", verdict("udp_other_peer") == "next")

print("== a host entry is exact")
run("bpftool", "map", "delete", "pinned", "/sys/fs/bpf/egress_stats", "key", "hex", *hx(u32(IF)))
allow6("2001:db9:1::5", 128)
check("IPv6: a /128 on the list lets that host through", verdict("syn6_host") == "next")
check("and not its neighbour in the same /64", verdict("syn6_neighbour") == "drop")

print("== isolation still wins")
run("bpftool", "map", "delete", "pinned", "/sys/fs/bpf/egress_stats", "key", "hex", *hx(u32(IF)))
mode(2, isolated=1)
check("an isolated tap drops what the policy would have let through", verdict("syn_in_list") == "drop")
check("and is not the policy's doing: an isolated tap's packets are not judged, so not counted against it", stats()["checked"] == 0, stats())
check("and the management network still passes", verdict("syn_mgmt") == "next")
mode(0, isolated=1)
check("with no policy an isolated tap behaves as it always did", verdict("syn_in_list") == "drop")

print("\npassed %d, failed %d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
PY
