#!/bin/bash
# Live guest test: boot a real KVM guest and check that a running shukrad sees what it sends.
#
# scripts/test-tap.sh proves the tap program on a real kernel with a network namespace
# standing in for the guest. This is the other half: a real QEMU/KVM guest, booted by fluxvm on
# a host bridge, sends TCP connects and UDP flows, and the events, the counters and the
# attach and detach are checked against what the kernel says.
#
# It creates two small VMs, the guest under test and a peer it talks to, and deletes them at the end. The VM also has a TTL, so fluxvm removes it
# even if this script is killed. It never touches another VM and never isolates anything.
#
# Run it on the hypervisor, as a user with sudo, where shukrad (with the tap program) and
# fluxvm are running. The guest is an Ubuntu cloud image; cloud-init makes it send, every 75
# seconds, one TCP SYN, twenty UDP datagrams on ONE flow, and three multicast datagrams.
#
#   scripts/test-live-guest.sh
#   BRIDGE=br0 IMAGE=/path/to/cloud.img scripts/test-live-guest.sh
#
#   SHUKRA_URL, SHUKRA_API_KEY   the daemon (the key defaults to the one in /etc/shukra/env)
#   IMAGE      a cloud image fluxvm can boot     BRIDGE   a host bridge with DHCP (virbr0)
#   FLUXCTL    the fluxvm CLI (fluxctl)          BOOT_WAIT  seconds to wait for the guest (240)
#   PEER_IP    the peer guest's address on the bridge's /24 (default: .202 on the bridge's network)
#   FLUXVM_TOML, FLUXVM_URL   where to find fluxvm's config and API, used only when the config has a
#              [sandbox.dataplane]: then the two test guests get a per-VM policy so they can reach each other
set -u
URL="${SHUKRA_URL:-http://127.0.0.1:30970}"
KEY="${SHUKRA_API_KEY:-$(sudo sed -n 's/^SHUKRA_API_KEY=//p' /etc/shukra/env 2>/dev/null | head -1)}"
IMAGE="${IMAGE:-/var/lib/fluxvm/images/noble-server-cloudimg-amd64.img}"
BRIDGE="${BRIDGE:-virbr0}"
FLUXCTL="${FLUXCTL:-fluxctl}"
BOOT_WAIT="${BOOT_WAIT:-240}"
NAME="shukra-live-$$"
NAMEB="$NAME-peer"
# Each tap guest needs its own MAC: fluxvm gives every one QEMU's default unless the spec sets one,
# and two guests on a bridge with the same MAC take each other's frames.
MACN=$(printf '%02x' $(( $$ % 250 + 1 )))
MAC_A="52:54:00:5a:$MACN:01"; MAC_B="52:54:00:5a:$MACN:02"
FLUXVM_TOML="${FLUXVM_TOML:-/etc/fluxvm.toml}"
FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"

PASS=0; FAILN=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAILN=$((FAILN+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }
api()  { curl -s -H "Authorization: Bearer $KEY" "$@"; }
J()    { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

D="$(mktemp -d /tmp/shukra-live.XXXXXX)"
ID=""; IDB=""
cleanup() {
  # An egress policy is a record on the daemon: never leave one behind for a VM that is about to be deleted.
  [ -n "${POLVM:-}" ] && api -X POST -d "{\"vm\":\"$POLVM\"}" "$URL/api/v1/policy/remove" >/dev/null 2>&1
  for i in "$ID" "$IDB"; do [ -n "$i" ] && sudo "$FLUXCTL" delete "$i" >/dev/null 2>&1; done
  rm -rf "$D"
}
trap cleanup EXIT

shukra_taps()  { api "$URL/api/v1/trace/tap" | J "len(d['rows'] or [])"; }
shukra_progs() { sudo bpftool net 2>/dev/null | grep -c shukra_tap; }
tap_row_of()   { api "$URL/api/v1/trace/tap" | J "[[r['fromGuestPackets'],r['toGuestPackets'],r['droppedPackets'],r['isolated']] for r in d['rows'] if r['tap']=='$1'][0]" 2>/dev/null; }
tap_row()      { tap_row_of "$TAP"; }
kern()         { echo "$(cat /sys/class/net/$TAP/statistics/rx_packets) $(cat /sys/class/net/$TAP/statistics/tx_packets)"; }

echo "== 0. preconditions"
check "fluxctl, bpftool, python3 and curl are present" "command -v $FLUXCTL >/dev/null && command -v python3 >/dev/null && command -v curl >/dev/null && sudo bpftool version >/dev/null 2>&1"
check "the cloud image exists" "[ -r '$IMAGE' ]"
check "the bridge $BRIDGE exists" "ip link show $BRIDGE >/dev/null 2>&1"
check "the daemon answers with this key" "[ \"\$(curl -s -o /dev/null -w %{http_code} -H 'Authorization: Bearer $KEY' $URL/api/v1/status)\" = 200 ]"
# With no VM yet the program reports "detached: no VM tap interfaces to attach to yet", which is
# fine: it attaches when the first tap appears. Any other detached reason (an old kernel, a
# missing capability) is a real problem.
check "the tap program is attached, or waiting for its first VM" "api $URL/api/v1/programs | J \"[p['status']+' '+p['detail'] for p in d['programs'] if p['name']=='tap'][0]\" | grep -qE '^attached|no VM tap'"
[ $FAILN -eq 0 ] || { echo "preconditions failed"; exit 1; }
TAPS0=$(shukra_taps); PROGS0=$(shukra_progs); PINS0=$(sudo ls /sys/fs/bpf/shukra/tap 2>/dev/null | wc -l)
echo "  baseline: $TAPS0 taps traced, $PROGS0 shukra TCX programs"

echo "== 1. boot two minimal guests: the one under test, and a peer it talks to"
# The peer listens on a fixed address on the bridge's /24, added as a second address next to its DHCP one.
BR_NET=$(ip -4 -o addr show dev "$BRIDGE" 2>/dev/null | awk '{print $4}' | head -1 | cut -d. -f1-3)
PEER_IP="${PEER_IP:-$BR_NET.202}"
if command -v virsh >/dev/null 2>&1 && sudo virsh net-dhcp-leases default 2>/dev/null | grep -q " $PEER_IP/"; then
  echo "  $PEER_IP is leased to another guest: set PEER_IP to a free address on $BRIDGE"; exit 1
fi
python3 - "$D" "$NAME" "$NAMEB" "$IMAGE" "$BRIDGE" "$MAC_A" "$MAC_B" "$PEER_IP" <<'PY'
import json, sys
d, name, nameb, image, bridge, mac_a, mac_b, peer = sys.argv[1:9]
common = '''import socket, struct, time
def say(m):
    try:
        open("/dev/console", "w").write("SHUKRA-LIVE %s\\n" % m)
    except Exception:
        pass
'''
gen = common + '''def route():
    try:
        return any(l.split()[1] == "00000000" for l in open("/proc/net/route").read().splitlines()[1:])
    except Exception:
        return False
for _ in range(180):
    if route():
        break
    time.sleep(1)
def tcp(ip, port):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect((ip, port))
    except Exception:
        pass
    s.close()
def udp(ip, port, n, sport=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if sport:
            s.bind(("0.0.0.0", sport))
        for _ in range(n):
            s.sendto(b"shukra", (ip, port))
    except Exception:
        pass
    s.close()
tcp("203.0.113.9", 443)
udp("203.0.113.53", 5301, 20, 40000)
udp("224.0.0.251", 5353, 3)
# DNS queries, built by hand and sent to an address nothing answers: only the question matters. The same
# name in two spellings and repeated is one A event per cycle; AAAA is its own.
def dnsq(name, qtype, n):
    q = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    for l in name.split("."):
        q += bytes([len(l)]) + l.encode()
    q += bytes([0]) + qtype.to_bytes(2, "big") + bytes([0, 1])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _ in range(n):
            s.sendto(q, ("203.0.113.53", 53))
    except Exception:
        pass
    s.close()
dnsq("live-probe.shukra-test.invalid", 1, 3)
dnsq("Live-Probe.Shukra-Test.INVALID", 1, 2)
dnsq("live-probe.shukra-test.invalid", 28, 1)
# A TLS ClientHello, built by hand and sent to the peer guest (which accepts the connection, and that is all a
# hello needs): the server name in mixed case, and one protocol. No byte here needs an escape.
def tlsh(ip, port, name, alpn):
    def ext(t, d):
        return struct.pack(">HH", t, len(d)) + d
    n = name.encode()
    p = alpn.encode()
    exts = ext(0, struct.pack(">HBH", len(n) + 3, 0, len(n)) + n) + ext(16, struct.pack(">HB", len(p) + 1, len(p)) + p)
    body = bytes([3, 3]) + bytes(32) + bytes([0]) + struct.pack(">H", 2) + bytes([0x13, 1]) + bytes([1, 0]) + struct.pack(">H", len(exts)) + exts
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    rec = bytes([0x16, 3, 1]) + struct.pack(">H", len(hs)) + hs
    try:
        s = socket.create_connection((ip, port), 3)
        s.sendall(rec)
        time.sleep(0.3)
        s.close()
    except Exception:
        pass
tlsh("@PEER@", 9000, "Live-TLS.Shukra-Test.INVALID", "h2")
# From the fourth cycle on, something this VM has never done: a network and a site it has not used. A daemon
# running learned baselines with a short learning period reports both once; otherwise it is only more traffic.
try:
    cycle = int(open("/var/tmp/shukra-cycle").read())
except Exception:
    cycle = 0
open("/var/tmp/shukra-cycle", "w").write(str(cycle + 1))
if cycle >= 3:
    tcp("198.51.100.7", 443)
    dnsq("late-probe.other-test.invalid", 1, 1)
# and talk to the peer guest, which may still be booting
for i in range(20):
    try:
        s = socket.create_connection(("@PEER@", 9000), 3)
        s.send(b"hello-from-the-guest-under-test")
        say("client: reply=" + s.recv(100).decode())
        s.close()
        break
    except Exception as e:
        say("client: try %d failed: %s" % (i, e))
        time.sleep(3)
# and a closed port on the peer: the peer's kernel answers RST, which is a refused connection
try:
    socket.create_connection(("@PEER@", 9001), 3)
except Exception:
    pass
'''.replace("@PEER@", peer)
server = common + '''import os, subprocess
dev = [x for x in os.listdir("/sys/class/net") if x.startswith("en")][0]
r = subprocess.run(["ip", "addr", "add", "@PEER@/24", "dev", dev], capture_output=True, text=True)
say("server: address add rc=%s" % r.returncode)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(5)
say("server: listening")
while True:
    c, a = s.accept()
    d = c.recv(100)
    say("server: got %s from %s" % (d.decode(), a[0]))
    c.send(b"ack:" + d); c.close()
'''.replace("@PEER@", peer)
def spec(n, mac, path, content, run):
    return {"name": n, "backend": "qemu", "image": image, "vcpus": 1, "memory_mib": 768, "disk_size_gib": 5,
            "ttl_seconds": 1800,
            "network": {"mode": "tap", "bridge": bridge, "netns": False, "mac": mac},
            "cloud_init": {"hostname": n, "user": "shukra",
                           "write_files": [{"path": path, "content": content, "permissions": "0644"}],
                           "runcmd": [run]}}
json.dump(spec(name, mac_a, "/opt/shukra-gen.py", gen,
               "nohup setsid sh -c 'while :; do python3 /opt/shukra-gen.py; sleep 75; done' >/var/log/shukra-gen.log 2>&1 &"),
          open(d + "/a.json", "w"))
json.dump(spec(nameb, mac_b, "/opt/shukra-peer.py", server, "nohup setsid python3 /opt/shukra-peer.py >/dev/null 2>&1 &"),
          open(d + "/b.json", "w"))
PY
create() { sudo "$FLUXCTL" create --spec "$1" 2>>"$D/create.err" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null; }
ID=$(create "$D/a.json"); IDB=$(create "$D/b.json")
check "fluxvm created both VMs" "[ -n '$ID' ] && [ -n '$IDB' ]"
[ -n "$ID" ] && [ -n "$IDB" ] || { grep -v WARN "$D/create.err" | head -5; exit 1; }

# Some hosts run a fluxvm dataplane (eBPF on each guest tap) that allows only the CIDRs and ports in
# /etc/fluxvm.toml, so a guest could not reach another on port 9000, or a public address at all. These
# two guests, and only these two, get their own policy: private CIDRs, no port restriction. A host
# without a dataplane needs nothing. The token is read here and never printed, and never appears in
# a check, because a failed check prints its command.
if sudo grep -q '^\[sandbox.dataplane\]' "$FLUXVM_TOML" 2>/dev/null; then
  FTOKEN=$(sudo sed -n 's/^token = "\(.*\)"/\1/p' "$FLUXVM_TOML" 2>/dev/null | head -1)
  POLICY=200
  # A VM that has only just been created may not have its network up yet, so the request is repeated for up to
  # a minute. The body of a refusal is kept (it does not contain the token) so the reason can be read.
  for pid in $ID $IDB; do
    c=000
    for _ in $(seq 1 30); do
      c=$(curl -s -o "$D/policy.body" -w '%{http_code}' -X POST -H "Authorization: Bearer $FTOKEN" -H 'Content-Type: application/json' \
        -d '{"default_allow": true, "allow_cidrs": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"], "allow_ports": []}' "$FLUXVM_URL/v1/vms/$pid/network/policy")
      [ "$c" = 200 ] && break
      sleep 2
    done
    [ "$c" = 200 ] || { POLICY=$c; echo "  fluxvm refused the policy for $pid ($c): $(head -c 300 "$D/policy.body")"; }
  done
  unset FTOKEN
  echo "  this host's fluxvm has a dataplane: the two test guests got their own policy (private CIDRs, no port limit)"
  check "fluxvm accepted the per-VM policy for both guests" "[ '$POLICY' = 200 ]"
fi
pid_of() { for _ in $(seq 1 30); do p=$(sudo "$FLUXCTL" get "$1" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('pid') or '')" 2>/dev/null); [ -n "$p" ] && { echo "$p"; return; }; sleep 1; done; }
QPID=$(pid_of "$ID"); QPIDB=$(pid_of "$IDB")
check "both VMs are running QEMU processes" "[ -n '$QPID' ] && [ -d /proc/$QPID ] && [ -n '$QPIDB' ] && [ -d /proc/$QPIDB ]"
check "they are real KVM guests" "sudo tr '\\0' ' ' < /proc/$QPID/cmdline | grep -q -- '-enable-kvm\\|accel=kvm' && sudo tr '\\0' ' ' < /proc/$QPIDB/cmdline | grep -q -- '-enable-kvm\\|accel=kvm'"

echo "== 2. shukra finds both VMs and their taps"
find_tap() { # pid -> "name tap"
  for _ in $(seq 1 40); do
    R=$(api "$URL/api/v1/vms" | J "[(v['name'],v['taps'][0]) for v in d['vms'] if v['pid']==$1 and v.get('taps')]" 2>/dev/null)
    case "$R" in "[('"*) echo "$R" | python3 -c "import sys,ast;print(*ast.literal_eval(sys.stdin.read())[0])"; return;; esac
    sleep 2
  done
}
read -r VMNAME TAP <<<"$(find_tap "$QPID")"
read -r VMNAMEB TAPB <<<"$(find_tap "$QPIDB")"
check "shukra lists both VMs with a tap (found from their command lines or fds)" "[ -n '$TAP' ] && [ -n '$TAPB' ] && [ '$TAP' != '$TAPB' ]"
[ -n "$TAP" ] && [ -n "$TAPB" ] || exit 1
echo "  guest under test: '$VMNAME' pid $QPID tap $TAP    peer: '$VMNAMEB' pid $QPIDB tap $TAPB ($PEER_IP)"
check "both taps are in the host's network namespace (the only place shukra can attach)" "[ -d /sys/class/net/$TAP ] && [ -d /sys/class/net/$TAPB ]"
for _ in $(seq 1 20); do shukra_taps | grep -q "^$((TAPS0+2))$" && break; sleep 2; done
check "the tap program attached to both, as hot-plugs (two more taps traced)" "[ \"\$(shukra_taps)\" = $((TAPS0+2)) ]"
check "and with four more TCX programs (ingress and egress on each)" "[ \"\$(shukra_progs)\" = $((PROGS0+4)) ]"
check "nothing is isolated or dropped on either" "[ \"\$(tap_row)\" != '' ] && tap_row | grep -q 'False\\]$' && [ \"\$(tap_row | cut -d, -f3 | tr -d ' ')\" = 0 ] && tap_row_of $TAPB | grep -q 'False\\]$' && [ \"\$(tap_row_of $TAPB | cut -d, -f3 | tr -d ' ')\" = 0 ]"

echo "== 3. the guest boots and sends (waiting up to ${BOOT_WAIT}s; a cloud image takes a minute or two)"
cat > "$D/collect.py" <<'PY'
# Poll the event stream and keep every guest event on this tap, once, until told to stop.
import json, sys, time, urllib.request
url, key, tap, out, secs, stop_early = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5]), sys.argv[6] == "1"
seen, last, end = {}, 0, time.time() + secs
try:
    seen = {json.loads(l)["seq"]: 1 for l in open(out)}
except Exception:
    pass
while time.time() < end:
    try:
        req = urllib.request.Request("%s/api/v1/events?since=%d" % (url, last), headers={"Authorization": "Bearer " + key})
        d = json.load(urllib.request.urlopen(req, timeout=5))
        last = max([last] + [e["seq"] for e in d["events"]])
        with open(out, "a") as f:
            for e in d["events"]:
                if e["kind"] in ("guest_connect", "guest_flow", "guest_dns", "guest_tls") and e.get("iface") == tap and e["seq"] not in seen:
                    seen[e["seq"]] = 1
                    f.write(json.dumps(e) + "\n")
    except Exception:
        pass
    if stop_early:
        # The guest also talks for its own reasons while it boots (DNS, apt), so wait for
        # this test's own traffic, not for any traffic.
        got = set()
        for l in open(out):
            e = json.loads(l)
            got.add((e["kind"], e.get("dst"), e.get("dport")))
        if {("guest_connect", "203.0.113.9", 443), ("guest_flow", "203.0.113.53", 5301)} <= got:
            break
    time.sleep(2)
PY
# An egress policy in audit mode on the guest under test: its peer and the bridge's gateway are on the list, and
# nothing else, so the guest's connect to 203.0.113.9 and its flows to 203.0.113.53 are outside it. Audit drops
# nothing and needs no management allow list, so this changes nothing the guest can do.
POLVM="$VMNAME"
POLICY_CODE=$(api -s -o /dev/null -w '%{http_code}' -X POST -d "{\"vm\":\"$VMNAME\",\"mode\":\"audit\",\"allow\":[\"$PEER_IP/32\",\"$BR_NET.1/32\"]}" "$URL/api/v1/policy/apply")
check "an egress policy in audit mode is accepted for the guest under test" "[ '$POLICY_CODE' = 200 ]"
check "the program on its tap is in audit mode" "api $URL/api/v1/policy?vm=$VMNAME | J \"[t['kernel'] for t in d['policies'][0]['taps']]\" | grep -q \"'audit'\""

: > "$D/guest.jsonl"
python3 "$D/collect.py" "$URL" "$KEY" "$TAP" "$D/guest.jsonl" "$BOOT_WAIT" 1
check "this test's own TCP connect and UDP flow both arrived as events" "grep -q '\"dst\": \"203.0.113.9\"' $D/guest.jsonl && grep -q '\"dst\": \"203.0.113.53\"' $D/guest.jsonl"
if [ ! -s "$D/guest.jsonl" ]; then
  echo "  no guest events. The guest may still be booting, or has no DHCP on $BRIDGE. Its console log:"
  sudo tail -5 /var/lib/fluxvm/instances/$ID/*.log 2>/dev/null | cut -c1-160
fi

echo "== 4. one more full cycle (75s) of the guest's traffic, and the counters against the kernel"
read -r K0R K0T <<<"$(kern)"; S0=$(tap_row)
python3 "$D/collect.py" "$URL" "$KEY" "$TAP" "$D/guest.jsonl" 90 0
read -r K1R K1T <<<"$(kern)"; S1=$(tap_row)
S0F=$(echo "$S0" | tr -d '[] ' | cut -d, -f1); S0T=$(echo "$S0" | tr -d '[] ' | cut -d, -f2)
S1F=$(echo "$S1" | tr -d '[] ' | cut -d, -f1); S1T=$(echo "$S1" | tr -d '[] ' | cut -d, -f2)
echo "  from the guest: shukra +$((S1F-S0F)) packets, kernel rx +$((K1R-K0R))    to the guest: shukra +$((S1T-S0T)), kernel tx +$((K1T-K0T))"
check "the guest sent something in the window (the comparison is not vacuous)" "[ $((K1R-K0R)) -ge 20 ]"
check "from-guest packets: shukra matches the kernel's rx count (within 5)" "[ \$(( ($S1F-$S0F) - ($K1R-$K0R) )) -ge -5 ] && [ \$(( ($S1F-$S0F) - ($K1R-$K0R) )) -le 5 ]"
check "to-guest packets: shukra matches the kernel's tx count (within 5)" "[ \$(( ($S1T-$S0T) - ($K1T-$K0T) )) -ge -5 ] && [ \$(( ($S1T-$S0T) - ($K1T-$K0T) )) -le 5 ]"

echo "== 5. what the events say"
cat > "$D/verify.py" <<'PY'
import json, sys
vm, tap = sys.argv[1], sys.argv[2]
peer_ip = sys.argv[4]
ev = [json.loads(l) for l in open(sys.argv[3])]
def sel(kind, dst, dport):
    return [e for e in ev if e["kind"] == kind and e.get("dst") == dst and e.get("dport") == dport]
tcp = sel("guest_connect", "203.0.113.9", 443)
udp = sel("guest_flow", "203.0.113.53", 5301)
mc = [e for e in ev if e.get("dst") == "224.0.0.251"]
peer = sel("guest_connect", peer_ip, 9000)
print("peer", len(peer))
print("peerattr", int(bool(peer) and all(e["guest_attributed"] and e["attribution"] == "guest-tap" and e.get("proto") == "tcp" and e["vm"]["name"] == vm for e in peer)))
print("tcp", len(tcp), "udp", len(udp), "mcast", len(mc), "all", len(ev))
print("attributed", int(bool(ev) and all(e["guest_attributed"] and e["attribution"] == "guest-tap" and e["vm"]["name"] == vm for e in ev)))
print("tcpproto", int(bool(tcp) and all(e.get("proto") == "tcp" for e in tcp)))
print("udpproto", int(bool(udp) and all(e.get("proto") == "udp" for e in udp)))
print("srcs", int(bool(ev) and all(str(e.get("src", "")).startswith("192.168.") or str(e.get("src", "")).startswith("10.") or str(e.get("src", "")).startswith("172.") for e in ev)))
print("notblocked", int(all(not e.get("blocked") for e in ev)))
dns = [e for e in ev if e["kind"] == "guest_dns"]
dna = [e for e in dns if e.get("dns_name") == "live-probe.shukra-test.invalid" and e.get("qtype") == "A"]
dnaaaa = [e for e in dns if e.get("dns_name") == "live-probe.shukra-test.invalid" and e.get("qtype") == "AAAA"]
print("dnsA", len(dna), "dnsAAAA", len(dnaaaa), "dnsall", len(dns))
print("dnsok", int(bool(dna) and all(e.get("dst") == "203.0.113.53" and e.get("dport") == 53 and e.get("proto") == "udp" and e["guest_attributed"] and e["vm"]["name"] == vm and not e.get("dns_truncated") for e in dna)))
tlsv = [e for e in ev if e["kind"] == "guest_tls" and e.get("sni") == "live-tls.shukra-test.invalid"]
print("tls", len(tlsv))
print("tlsok", int(bool(tlsv) and all(e.get("dst") == peer_ip and e.get("dport") == 9000 and e.get("proto") == "tcp" and e.get("alpn") == "h2" and e.get("tls_version") == "1.2" and len(e.get("ja3", "")) == 32 and not e.get("tls_truncated") and e["guest_attributed"] and e["vm"]["name"] == vm for e in tlsv)))
aud = [e for e in ev if e.get("policy") == "audit"]
aud_dst = {e.get("dst") for e in aud}
print("policy", len(aud), int("203.0.113.9" in aud_dst and "203.0.113.53" in aud_dst), int(peer_ip not in aud_dst and "192.168.122.1" not in aud_dst))
for e in ev[:8]:
    print("show %-13s %-4s %s -> %s:%s attributed=%s attr=%s" % (e["kind"], e.get("proto"), e.get("src"), e.get("dst"), e.get("dport"), e["guest_attributed"], e["attribution"]))
PY
python3 "$D/verify.py" "$VMNAME" "$TAP" "$D/guest.jsonl" "$PEER_IP" > "$D/verify.out"
grep '^show' "$D/verify.out" | sed 's/^show /    /'
val() { sed -n "s/^$1 //p" "$D/verify.out" | head -1; }
NT=$(sed -n 's/^tcp \([0-9]*\) .*/\1/p' "$D/verify.out")
NU=$(sed -n 's/^tcp .* udp \([0-9]*\) .*/\1/p' "$D/verify.out")
NM=$(sed -n 's/^tcp .* mcast \([0-9]*\) .*/\1/p' "$D/verify.out")
check "a TCP connect from the guest is a guest_connect event with proto tcp" "[ '$NT' -ge 2 ] && [ \"\$(val tcpproto)\" = 1 ]"
check "a UDP flow from the guest is a guest_flow event with proto udp" "[ '$NU' -ge 2 ] && [ \"\$(val udpproto)\" = 1 ]"
check "every guest event is guest_attributed, attribution guest-tap, and names this VM" "[ \"\$(val attributed)\" = 1 ]"
check "the source is the guest's own address, not the host's" "[ \"\$(val srcs)\" = 1 ]"
check "twenty datagrams on one flow per cycle are one event per cycle, not twenty (udp events $NU, cycles $NT)" "[ '$NU' -ge 1 ] && [ \$(( $NT - $NU )) -ge 0 ] && [ \$(( $NT - $NU )) -le 1 ]"
check "multicast is counted but produces no event" "[ '$NM' = 0 ]"
NDA=$(sed -n 's/^dnsA \([0-9]*\) .*/\1/p' "$D/verify.out")
NDAAAA=$(sed -n 's/^dnsA .* dnsAAAA \([0-9]*\) .*/\1/p' "$D/verify.out")
check "the guest's DNS lookup arrives as a guest_dns event with exactly the name it asked for, lower-cased, and its type (A events $NDA, AAAA $NDAAAA)" "[ '$NDA' -ge 1 ] && [ '$NDAAAA' -ge 1 ] && [ \"\$(val dnsok)\" = 1 ]"
check "five lookups of one name in two spellings are one event per cycle, not five (A events $NDA, cycles $NT)" "[ \$(( $NT - $NDA )) -ge 0 ] && [ \$(( $NT - $NDA )) -le 1 ]"
check "the guest's connect and flow to places its egress policy does not list are events marked audit" "[ \"\$(sed -n 's/^policy [0-9]* \\([01]\\) [01]\$/\\1/p' $D/verify.out)\" = 1 ]"
check "and what it does that the policy does list (its peer, the gateway) is not marked" "[ \"\$(sed -n 's/^policy [0-9]* [01] \\([01]\\)\$/\\1/p' $D/verify.out)\" = 1 ]"
check "the policy's counters say what audit would have dropped, that it judged more than that, and that nothing was dropped" "api $URL/api/v1/policy?vm=$VMNAME | J \"(lambda t: t['auditPackets']>=2 and t['checked']>t['auditPackets'] and t['droppedPackets']==0)(d['policies'][0]['taps'][0])\" | grep -q True"
check "it is a low detection, guest-attributed, naming the guest and the place" "api $URL/api/v1/events | J \"any(e['guest_attributed'] and e['vm']['name']=='$VMNAME' and e['severity']=='low' and '203.0.113.9:443' in e['message'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='egress-policy-audit')\" | grep -q True"
NTLS=$(sed -n 's/^tls \([0-9]*\)$/\1/p' "$D/verify.out")
check "the guest's TLS hello arrives as a guest_tls event with the name it asked for, lower-cased, its protocol and a fingerprint (events $NTLS)" "[ '$NTLS' -ge 1 ] && [ \"\$(val tlsok)\" = 1 ]"
check "and it is one event per connection, not more (events $NTLS, cycles $NT)" "[ '$NTLS' -le '$NT' ]"
check "no event on an ordinary run is marked blocked (nothing is isolated)" "[ \"\$(val notblocked)\" = 1 ]"
check "host tcp_connect events are still not guest-attributed" "api $URL/api/v1/events | J \"any(e['guest_attributed'] for e in d['events'] if e['kind']=='tcp_connect')\" | grep -q False"
check "the guest's vCPU preemption is measured: a row with a preemptor list (never null), and a time below the VM's lifetime" "api $URL/api/v1/trace/sched | J \"[(r['vcpuPreemptedNs'], isinstance(r['topPreemptors'], list)) for r in d['rows'] if r['vm']=='$VMNAME'][0]\" | awk -F'[(), ]+' '\$3==\"True\" && \$2<300000000000{f=1} END{exit !f}'"
check "the VMM tripwire program is attached" "api $URL/api/v1/programs | J \"[p['status'] for p in d['programs'] if p['name']=='vmm'][0]\" | grep -q attached"
check "the guest's QEMU process is on its watched list in the kernel (tgid $QPID)" "sudo bpftool -j map dump name vmm_watched 2>/dev/null | python3 -c \"import sys,json,struct; print(any(struct.unpack('<I', bytes(int(x,16) for x in e['key']))[0]==$QPID for e in json.load(sys.stdin)))\" | grep -q True"
check "a real QEMU raised no tripwire detection while it booted, ran, and talked to its peer: no false alarm" "api $URL/api/v1/events | J \"[e.get('rule') for e in d['events'] if e['kind']=='detection' and str(e.get('rule','')).startswith('vmm-') and e['vm']['name'] in ('$VMNAME','$VMNAMEB')]\" | grep -q '^\\[\\]\$'"
# The real thing: ask this guest's own QEMU, over its own QMP socket, to open /etc/shadow (a read-only file node,
# removed again straight after). QEMU opens it as any VMM would that had been talked into it, so the tripwire must
# say so, critically, and name the VM. Only this guest's socket is used; nothing is written to the file.
QMPSOCK=$(sudo tr '\0' '\n' < /proc/$QPID/cmdline | sed -n 's/^unix:\(.*qmp[^,]*\),.*/\1/p' | head -1)
if [ -n "$QMPSOCK" ] && sudo test -S "$QMPSOCK"; then
  cat > "$D/qmp.py" <<'QMP'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sys.argv[1]); f = s.makefile("rw")
json.loads(f.readline())
def call(cmd, args=None):
    f.write(json.dumps({"execute": cmd, **({"arguments": args} if args else {})}) + "\n"); f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
call("qmp_capabilities")
r = call("blockdev-add", {"driver": "file", "node-name": "shukra-tripwire", "filename": "/etc/shadow", "read-only": True})
print("blockdev-add", "error" if "error" in r else "ok")
call("blockdev-del", {"node-name": "shukra-tripwire"})
QMP
  sudo python3 "$D/qmp.py" "$QMPSOCK" > "$D/qmp.out" 2>&1
  check "QEMU answered the QMP request ($(tr '\n' ' ' < "$D/qmp.out"))" "grep -q '^blockdev-add' '$D/qmp.out'"
  for _ in $(seq 1 20); do
    api $URL/api/v1/events | J "any(e['kind']=='detection' and e.get('rule')=='vmm-sensitive-open' and e['vm']['name']=='$VMNAME' for e in d['events'])" 2>/dev/null | grep -q True && break; sleep 1
  done
  check "QEMU opening /etc/shadow raises a critical vmm-sensitive-open detection for this VM, on the VMM and not the guest" "api $URL/api/v1/events | J \"any(e['kind']=='detection' and e.get('rule')=='vmm-sensitive-open' and e['severity']=='critical' and e['vm']['name']=='$VMNAME' and not e.get('guest_attributed') and '/etc/shadow' in str(e) for e in d['events'])\" | grep -q True"
else
  echo "  SKIP  no QMP socket on this QEMU's command line: the real-QEMU tripwire check was not run"
fi
check "shukra still traces the KVM exits of this VM" "api $URL/api/v1/trace/kvm | J \"sum(r['exits'] for r in d['rows'])\" | awk '\$1>0{f=1} END{exit !f}'"

echo "== 5a. learned baselines (only when the daemon has them on with a learning period of five minutes or less)"
BASE_OK=$(api $URL/api/v1/baseline | J "int(bool(d['enabled'] and __import__('re').match(r'^[0-5]m0s\$', d['learn'])))" 2>/dev/null)
if [ "$BASE_OK" = 1 ]; then
  # The learning period ends a few minutes after the guest first talks; the fourth cycle then brings the new things.
  for _ in $(seq 1 60); do
    api $URL/api/v1/events | J "any(e.get('rule')=='new-destination' and '198.51.100.0/24' in e['message'] for e in d['events'] if e['kind']=='detection') and any(e.get('rule')=='new-dns-suffix' and 'other-test.invalid' in e['message'] for e in d['events'] if e['kind']=='detection')" 2>/dev/null | grep -q True && break
    sleep 5
  done
  check "a network this guest never used, after its learning period, is one new-destination detection naming the network and the address, attributed to the guest's tap" "api $URL/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='new-destination' and '198.51.100.0/24' in e['message'] and '198.51.100.7:443' in e['message'] and e['guest_attributed'] and e['attribution']=='guest-tap'])\" | grep -q '^1\$'"
  check "and a site it never looked up is one new-dns-suffix detection naming the suffix" "api $URL/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='new-dns-suffix' and 'other-test.invalid' in e['message'] and 'late-probe.other-test.invalid' in e['message']])\" | grep -q '^1\$'"
  check "what it did before its learning period ended raised nothing: no new-destination for the networks the cycle used from the start" "api $URL/api/v1/events | J \"[e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='new-destination' and ('203.0.113.0/24' in e['message'])]\" | grep -q '^\[\]\$'"
  check "the baseline lists what was learned for the VM" "api '$URL/api/v1/baseline?vm=$VMNAME&items=1' | J \"len([i for i in d['items'] if i['kind']=='destination'])\" | awk '\$1>=2{f=1} END{exit !f}'"
else
  echo "  skipped: the daemon's rules file has no baselines section, or its learning period is longer than five minutes"
fi

echo "== 5b. the two guests reach each other, and shukra sees both ends"
LOGA=/var/lib/fluxvm/instances/$ID/console.log; LOGB=/var/lib/fluxvm/instances/$IDB/console.log
for _ in $(seq 1 30); do sudo grep -aq 'SHUKRA-LIVE server: got' "$LOGB" 2>/dev/null && break; sleep 2; done
check "the peer received the message the guest under test sent it" "sudo grep -a 'SHUKRA-LIVE server: got' $LOGB | grep -q 'hello-from-the-guest-under-test'"
check "and the guest under test got the peer's answer back" "sudo grep -aq 'SHUKRA-LIVE client: reply=ack:hello-from-the-guest-under-test' $LOGA"
NPEER=$(val peer)
check "shukra saw that connect as a guest_connect on the sender's tap, tcp, guest-attributed, naming the sender" "[ '$NPEER' -ge 1 ] && [ \"\$(val peerattr)\" = 1 ]"
check "the peer's tap carried its reply (from-guest packets, none dropped)" "[ \"\$(tap_row_of $TAPB | cut -d, -f1 | tr -d '[] ')\" -ge 1 ] && [ \"\$(tap_row_of $TAPB | cut -d, -f3 | tr -d ' ')\" = 0 ]"
check "and nothing was dropped on the sender's tap either" "[ \"\$(tap_row | cut -d, -f3 | tr -d ' ')\" = 0 ]"

# What became of the TCP connections, as the two taps saw them. The guest connected to the peer's open port
# (accepted) and to a closed one (refused); the peer's tap sees the same two connections coming in.
outc() { api "$URL/api/v1/trace/tap" | J "[r['$2'] for r in d['rows'] if r['tap']=='$1'][0]"; }
check "the guest's connection to the peer was accepted, and its connection to a closed peer port was refused" "[ \"\$(outc $TAP outAccepted)\" -ge 1 ] && [ \"\$(outc $TAP outRefused)\" -ge 1 ]"
check "the peer's tap saw the same two connections from its side, coming in: one accepted, one refused" "[ \"\$(outc $TAPB inAccepted)\" -ge 1 ] && [ \"\$(outc $TAPB inRefused)\" -ge 1 ]"
check "every accepted connection is in the handshake histogram, and none took as long as five seconds" "api $URL/api/v1/trace/tap | J \"[(sum(r['handshakeHist']), r['outAccepted'], r['handshakeP99Ns']) for r in d['rows'] if r['tap']=='$TAP'][0]\" | awk -F'[(), ]+' '\$2==\$3 && \$2>0 && \$4<5000000000{f=1} END{exit !f}'"
check "the guest's attempts are all accounted for (accepted + refused + never answered + blocked), give or take those still waiting" "[ \$(( \$(outc $TAP outSyn) - \$(outc $TAP outAccepted) - \$(outc $TAP outRefused) - \$(outc $TAP outTimedOut) - \$(outc $TAP outBlocked) )) -le 6 ]"
echo "  the guest's connections: $(api "$URL/api/v1/trace/tap" | J "[(r['outSyn'],r['outAccepted'],r['outRefused'],r['outTimedOut'],r['outBlocked'],r['handshakeP50Ns']) for r in d['rows'] if r['tap']=='$TAP']")  (attempts, accepted, refused, never answered, blocked, handshake p50 ns)"

# The drops program counts what the kernel dropped on the taps. Whether anything else dropped traffic
# depends on the host (fluxvm's dataplane, when it has one, legitimately drops the guest's traffic to a
# public address), so this asserts that it is measuring and names both taps, and prints the numbers.
check "the drops program is measuring and lists both guests' taps" "api $URL/api/v1/trace/drops | J \"d['measured'] and {'$TAP','$TAPB'} <= {t['tap'] for t in d['taps']}\" | grep -q True"
echo "  kernel drops on the two taps (tap, kernel, shukra's, someone else's, guest not reading): $(api "$URL/api/v1/trace/drops" | J "[(t['tap'],t['kernelDrops'],t['shukraDropped'],t['otherDrops'],t['guestNotReading']) for t in d['taps'] if t['tap'] in ('$TAP','$TAPB')]")"
echo "  by reason, and the function that freed them: $(api "$URL/api/v1/trace/drops" | J "[(r['tap'],r['reason'],r['count'],r.get('location','')) for r in d['rows'] if r['tap'] in ('$TAP','$TAPB')]")"
# If something other than Shukra dropped packets, say what else is attached to the tap: that is the suspect.
for tp in $TAP $TAPB; do
  echo "  attached to $tp besides Shukra's programs: $(sudo bpftool net show dev "$tp" 2>/dev/null | grep -E 'clsact|tcx|xdp' | grep -v shukra_tap | tr -s ' ' | sed 's/^ //' | tr '\n' ';')"
done


echo "== 5c. the policy is taken off again, and leaves nothing behind"
api -s -o /dev/null -X POST -d "{\"vm\":\"$VMNAME\"}" "$URL/api/v1/policy/remove"; POLVM=""
check "removing it leaves no policy for the guest, and the program on its tap is off" "api $URL/api/v1/policy | J \"[p['vm'] for p in d['policies']]\" | grep -qv \"$VMNAME\" && api $URL/api/v1/policy | J \"len(d['orphans'])\" | grep -q '^0\$'"

echo "== 6. delete both VMs: the tap programs come off"
sudo "$FLUXCTL" delete "$ID" >/dev/null 2>&1; ID=""
sudo "$FLUXCTL" delete "$IDB" >/dev/null 2>&1; IDB=""
# The tap device goes with the VM at once, but shukra notices on its next scan, which is when
# it drops the VM from its list and removes the pins of a tap that no longer exists. So wait
# for all three, and print what was seen if that never happens.
vm_gone() { api "$URL/api/v1/vms" | J "len([v for v in d['vms'] if v['pid'] in ($QPID, $QPIDB)])" | grep -qx 0; }
pins()    { sudo ls /sys/fs/bpf/shukra/tap 2>/dev/null | wc -l; }
for _ in $(seq 1 30); do
  [ "$(shukra_taps)" = "$TAPS0" ] && vm_gone && [ "$(pins)" = "$PINS0" ] && break; sleep 2
done
echo "  after delete: $(shukra_taps) taps traced, $(shukra_progs) TCX programs, $(pins) pins (baseline $TAPS0, $PROGS0, $PINS0), VM listed: $(vm_gone && echo no || echo YES)"
check "the tap is no longer traced" "[ \"\$(shukra_taps)\" = $TAPS0 ]"
check "the TCX programs are gone again ($PROGS0, as before)" "[ \"\$(shukra_progs)\" = $PROGS0 ]"
check "both VMs are gone from shukra" "vm_gone"
check "the pinned links are back to what they were ($PINS0)" "[ \"\$(pins)\" = $PINS0 ]"

echo; echo "passed $PASS, failed $FAILN"
[ $FAILN -eq 0 ]
