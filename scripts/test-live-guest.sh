#!/bin/bash
# Live guest test: boot a real KVM guest and check that a running shukrad sees what it sends.
#
# scripts/test-tap.sh proves the tap program on a real kernel with a network namespace
# standing in for the guest. This is the other half: a real QEMU/KVM guest, booted by fluxvm on
# a host bridge, sends TCP connects and UDP flows, and the events, the counters and the
# attach and detach are checked against what the kernel says.
#
# It creates one small VM and deletes it at the end. The VM also has a TTL, so fluxvm removes it
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
set -u
URL="${SHUKRA_URL:-http://127.0.0.1:30970}"
KEY="${SHUKRA_API_KEY:-$(sudo sed -n 's/^SHUKRA_API_KEY=//p' /etc/shukra/env 2>/dev/null | head -1)}"
IMAGE="${IMAGE:-/var/lib/fluxvm/images/noble-server-cloudimg-amd64.img}"
BRIDGE="${BRIDGE:-virbr0}"
FLUXCTL="${FLUXCTL:-fluxctl}"
BOOT_WAIT="${BOOT_WAIT:-240}"
NAME="shukra-live-$$"

PASS=0; FAILN=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAILN=$((FAILN+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }
api()  { curl -s -H "Authorization: Bearer $KEY" "$@"; }
J()    { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

D="$(mktemp -d /tmp/shukra-live.XXXXXX)"
ID=""
cleanup() {
  [ -n "$ID" ] && sudo "$FLUXCTL" delete "$ID" >/dev/null 2>&1
  rm -rf "$D"
}
trap cleanup EXIT

shukra_taps()  { api "$URL/api/v1/trace/tap" | J "len(d['rows'])"; }
shukra_progs() { sudo bpftool net 2>/dev/null | grep -c shukra_tap; }
tap_row()      { api "$URL/api/v1/trace/tap" | J "[[r['fromGuestPackets'],r['toGuestPackets'],r['droppedPackets'],r['isolated']] for r in d['rows'] if r['tap']=='$TAP'][0]" 2>/dev/null; }
kern()         { echo "$(cat /sys/class/net/$TAP/statistics/rx_packets) $(cat /sys/class/net/$TAP/statistics/tx_packets)"; }

echo "== 0. preconditions"
check "fluxctl, bpftool, python3 and curl are present" "command -v $FLUXCTL >/dev/null && command -v python3 >/dev/null && command -v curl >/dev/null && sudo bpftool version >/dev/null 2>&1"
check "the cloud image exists" "[ -r '$IMAGE' ]"
check "the bridge $BRIDGE exists" "ip link show $BRIDGE >/dev/null 2>&1"
check "the daemon answers with this key" "[ \"\$(curl -s -o /dev/null -w %{http_code} -H 'Authorization: Bearer $KEY' $URL/api/v1/status)\" = 200 ]"
check "the tap program is attached" "api $URL/api/v1/programs | J \"[p['status'] for p in d['programs'] if p['name']=='tap'][0]\" | grep -q attached"
[ $FAILN -eq 0 ] || { echo "preconditions failed"; exit 1; }
TAPS0=$(shukra_taps); PROGS0=$(shukra_progs); PINS0=$(sudo ls /sys/fs/bpf/shukra/tap 2>/dev/null | wc -l)
echo "  baseline: $TAPS0 taps traced, $PROGS0 shukra TCX programs"

echo "== 1. boot a minimal guest"
python3 - "$D/spec.json" "$NAME" "$IMAGE" "$BRIDGE" <<'PY'
import json, sys
out, name, image, bridge = sys.argv[1:5]
gen = '''import socket, time
def route():
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
'''
spec = {
    "name": name, "backend": "qemu", "image": image, "vcpus": 1, "memory_mib": 768, "disk_size_gib": 5,
    "ttl_seconds": 1800,
    "network": {"mode": "tap", "bridge": bridge, "netns": False},
    "cloud_init": {
        "hostname": name, "user": "shukra",
        "write_files": [{"path": "/opt/shukra-gen.py", "content": gen, "permissions": "0644"}],
        "runcmd": ["nohup setsid sh -c 'while :; do python3 /opt/shukra-gen.py; sleep 75; done' >/var/log/shukra-gen.log 2>&1 &"],
    },
}
json.dump(spec, open(out, "w"))
PY
OUT=$(sudo "$FLUXCTL" create --spec "$D/spec.json" 2>"$D/create.err")
ID=$(echo "$OUT" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null)
check "fluxvm created the VM" "[ -n '$ID' ]"
[ -n "$ID" ] || { echo "$OUT" | head -5; grep -v WARN "$D/create.err" | head -5; exit 1; }
QPID=""
for _ in $(seq 1 30); do
  QPID=$(sudo "$FLUXCTL" get "$ID" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('pid') or '')" 2>/dev/null)
  [ -n "$QPID" ] && break; sleep 1
done
check "the VM is a running QEMU process" "[ -n '$QPID' ] && [ -d /proc/$QPID ]"
check "it is a real KVM guest" "sudo tr '\\0' ' ' < /proc/$QPID/cmdline | grep -q -- '-enable-kvm\\|accel=kvm'"

echo "== 2. shukra finds the VM and its tap"
TAP=""; VMNAME=""
for _ in $(seq 1 40); do
  R=$(api "$URL/api/v1/vms" | J "[(v['name'],v['taps'][0]) for v in d['vms'] if v['pid']==$QPID and v.get('taps')]" 2>/dev/null)
  case "$R" in "[('"*) VMNAME=$(echo "$R" | python3 -c "import sys,ast;print(ast.literal_eval(sys.stdin.read())[0][0])"); TAP=$(echo "$R" | python3 -c "import sys,ast;print(ast.literal_eval(sys.stdin.read())[0][1])"); break;; esac
  sleep 2
done
check "shukra lists the VM with a tap (found from its command line or fds)" "[ -n '$TAP' ]"
[ -n "$TAP" ] || exit 1
echo "  VM '$VMNAME' pid $QPID tap $TAP"
check "the tap is in the host's network namespace (the only place shukra can attach)" "[ -d /sys/class/net/$TAP ]"
for _ in $(seq 1 20); do shukra_taps | grep -q "^$((TAPS0+1))$" && break; sleep 2; done
check "the tap program attached to it, as a hot-plug (one more tap traced)" "[ \"\$(shukra_taps)\" = $((TAPS0+1)) ]"
check "and with two more TCX programs (ingress and egress)" "[ \"\$(shukra_progs)\" = $((PROGS0+2)) ]"
check "nothing is isolated or dropped on it" "[ \"\$(tap_row)\" != '' ] && tap_row | grep -q 'False\\]$' && [ \"\$(tap_row | cut -d, -f3 | tr -d ' ')\" = 0 ]"

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
                if e["kind"] in ("guest_connect", "guest_flow") and e.get("iface") == tap and e["seq"] not in seen:
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
ev = [json.loads(l) for l in open(sys.argv[3])]
def sel(kind, dst, dport):
    return [e for e in ev if e["kind"] == kind and e.get("dst") == dst and e.get("dport") == dport]
tcp = sel("guest_connect", "203.0.113.9", 443)
udp = sel("guest_flow", "203.0.113.53", 5301)
mc = [e for e in ev if e.get("dst") == "224.0.0.251"]
print("tcp", len(tcp), "udp", len(udp), "mcast", len(mc), "all", len(ev))
print("attributed", int(bool(ev) and all(e["guest_attributed"] and e["attribution"] == "guest-tap" and e["vm"]["name"] == vm for e in ev)))
print("tcpproto", int(bool(tcp) and all(e.get("proto") == "tcp" for e in tcp)))
print("udpproto", int(bool(udp) and all(e.get("proto") == "udp" for e in udp)))
print("srcs", int(bool(ev) and all(str(e.get("src", "")).startswith("192.168.") or str(e.get("src", "")).startswith("10.") or str(e.get("src", "")).startswith("172.") for e in ev)))
print("notblocked", int(all(not e.get("blocked") for e in ev)))
for e in ev[:8]:
    print("show %-13s %-4s %s -> %s:%s attributed=%s attr=%s" % (e["kind"], e.get("proto"), e.get("src"), e.get("dst"), e.get("dport"), e["guest_attributed"], e["attribution"]))
PY
python3 "$D/verify.py" "$VMNAME" "$TAP" "$D/guest.jsonl" > "$D/verify.out"
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
check "no event on an ordinary run is marked blocked (nothing is isolated)" "[ \"\$(val notblocked)\" = 1 ]"
check "host tcp_connect events are still not guest-attributed" "api $URL/api/v1/events | J \"any(e['guest_attributed'] for e in d['events'] if e['kind']=='tcp_connect')\" | grep -q False"
check "shukra still traces the KVM exits of this VM" "api $URL/api/v1/trace/kvm | J \"sum(r['exits'] for r in d['rows'])\" | awk '\$1>0{f=1} END{exit !f}'"

echo "== 6. delete the VM: the tap program comes off"
sudo "$FLUXCTL" delete "$ID" >/dev/null 2>&1; ID=""
for _ in $(seq 1 30); do [ "$(shukra_taps)" = "$TAPS0" ] && break; sleep 2; done
check "the tap is no longer traced" "[ \"\$(shukra_taps)\" = $TAPS0 ]"
check "the TCX programs are gone again ($PROGS0, as before)" "[ \"\$(shukra_progs)\" = $PROGS0 ]"
check "the VM is gone from shukra" "api $URL/api/v1/vms | J \"[v for v in d['vms'] if v['pid']==$QPID]\" | grep -q '\\[\\]'"
check "the pinned links are back to what they were ($PINS0)" "[ \"\$(sudo ls /sys/fs/bpf/shukra/tap 2>/dev/null | wc -l)\" = $PINS0 ]"

echo; echo "passed $PASS, failed $FAILN"
[ $FAILN -eq 0 ]
