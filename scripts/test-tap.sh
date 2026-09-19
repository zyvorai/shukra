#!/bin/bash
# End-to-end test of the tap program and isolation, on a real kernel.
#
# A network namespace plays the guest, joined to the host by a veth pair whose host
# end stands in for the VM's tap. A fake QEMU process names that interface on its
# command line, so the daemon treats it as the VM's tap. No /dev/kvm is needed.
#
# Needs Linux 6.6+ (TCX), root or passwordless sudo, ip, curl, python3, and a
# shukrad built with -tags shukrabpf (make generate first). Everything it creates
# is removed at the end.
#
#   scripts/test-tap.sh                # builds the daemon itself
#   SHUKRAD=bin/shukrad scripts/test-tap.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PASS=0; FAILN=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAILN=$((FAILN+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }

D="$(mktemp -d /tmp/shukra-tap.XXXXXX)"
BIN="${SHUKRAD:-}"
if [ -z "$BIN" ]; then
  BIN="$D/shukrad"
  go build -tags shukrabpf -o "$BIN" ./cmd/shukrad || { echo "build failed"; exit 1; }
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
cleanup() {
  sudo pkill -f "$BIN -listen" 2>/dev/null; sudo "$BIN" -detach-all >/dev/null 2>&1; sudo pkill -f "qemu-system-x86_64 .*(taptest|tunvm)" 2>/dev/null; sudo pkill -f "$D/holder.py" 2>/dev/null; sudo ip link del tapx 2>/dev/null; kill "$HTTP_PID" 2>/dev/null
  sudo ip netns del g1 2>/dev/null; sudo ip link del vethh 2>/dev/null; sudo rm -rf $D
}
trap cleanup EXIT
sudo pkill -f "$BIN -listen" 2>/dev/null; sudo ip netns del g1 2>/dev/null; sudo ip link del vethh 2>/dev/null

# --- the "guest": a namespace behind a veth pair whose host end is the tap
sudo ip netns add g1
sudo ip link add vethh type veth peer name vethg
sudo ip link set vethg netns g1
sudo ip addr add 10.99.0.1/24 dev vethh; sudo ip addr add 10.99.0.3/24 dev vethh
sudo ip -6 addr add fd99::1/64 dev vethh nodad; sudo ip -6 addr add fd99::3/64 dev vethh nodad
sudo ip link set vethh up
sudo ip -n g1 addr add 10.99.0.2/24 dev vethg; sudo ip -n g1 -6 addr add fd99::2/64 dev vethg nodad
sudo ip -n g1 link set vethg up; sudo ip -n g1 link set lo up
# host services on two addresses: .1 will be on the allow list, .3 will not
( cd "$D" && exec python3 -m http.server 8080 --bind :: >/dev/null 2>&1 ) &
HTTP_PID=$!
sleep 1
# a QEMU that says its tap is vethh
printf '#!/bin/bash\nwhile true; do /bin/true; sleep 0.2; done\n' > "$D/loop.sh"; chmod +x "$D/loop.sh"
bash -c "exec -a /usr/bin/qemu-system-x86_64 bash $D/loop.sh -name taptest -uuid 9999 -netdev tap,id=n0,ifname=vethh,script=no" >/dev/null 2>&1 &

printf 'destinations:\n  - cidr: 10.99.0.3/32\n    name: watched-host\n    severity: high\n' > $D/rules.yaml
A="Authorization: Bearer k"; U=127.0.0.1:30990
guest() { sudo ip netns exec g1 "$@"; }
code4() { guest curl -s -o /dev/null -m 2 -w %{http_code} "http://$1:8080/"; }
code6() { guest curl -s -6 -o /dev/null -m 2 -w %{http_code} "http://[$1]:8080/"; }
start() { sudo -b env SHUKRA_API_KEY=k "$BIN" -listen $U -web /nonexistent -data-dir $D/data -watchlist $D/rules.yaml "$@" > $D/daemon.log 2>&1; sleep 4; }
stopd() { sudo pkill -f "$BIN -listen"; sleep 1; }
api() { curl -s -H "$A" "$@"; }
J() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo "== 1. isolate is refused without a management allow list"
start
check "the tap program attached to the VM's tap" "api $U/api/v1/programs | J \"[p['status'] for p in d['programs'] if p['name']=='tap'][0]\" | grep -q attached"
check "the VM's tap was read from its command line" "api $U/api/v1/vms | J \"d['vms'][0]['taps']\" | grep -q vethh"
R=$(api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate)
check "isolate without an allow list is not applied" "echo '$R' | J \"d['applied']\" | grep -q False"
check "and says why" "echo '$R' | grep -qi 'allow list'"
check "traffic to a non-allowed address is unaffected" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
stopd

echo "== 2. guest traffic is seen on the tap and attributed to the guest"
start -isolate-allow 10.99.0.1/32,fd99::1/128
check "the guest reaches an allowed host before isolation" "[ \"\$(code4 10.99.0.1)\" = 200 ]"
check "the guest reaches the watched host before isolation" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
sleep 1
EV=$(api "$U/api/v1/events")
check "a guest_connect event names the VM, the guest's own address and the destination" \
  "echo '$EV' | J \"[e for e in d['events'] if e['kind']=='guest_connect' and e['dst']=='10.99.0.1' and e['dport']==8080][0]\" | grep -q \"'src': '10.99.0.2'\""
check "it is guest_attributed with attribution guest-tap" \
  "echo '$EV' | J \"[e for e in d['events'] if e['kind']=='guest_connect' and e['dst']=='10.99.0.1'][0]\" | grep -q \"'guest_attributed': True\""
check "it carries the VM and the interface" \
  "echo '$EV' | J \"[e for e in d['events'] if e['kind']=='guest_connect' and e['dst']=='10.99.0.1'][0]\" | grep -q \"'name': 'taptest'\""
# The rig's "guest" is a process on this host, so its curl also makes a host-side
# tcp_connect, which correctly gets its own unattributed detection. Either can
# arrive first, so ask whether any matching detection is the guest's.
check "the destination rule fired on the guest's connect, still guest-attributed" \
  "echo '$EV' | J \"any(e['guest_attributed'] and e['attribution']=='guest-tap' and e['vm']['name']=='taptest' for e in d['events'] if e['kind']=='detection' and e.get('rule')=='watched-host')\" | grep -q True"
check "the host-side detection for the same address is not called the guest's" \
  "echo '$EV' | J \"all(not e['guest_attributed'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='watched-host' and e['attribution']!='guest-tap')\" | grep -q True"
check "host-side tcp_connect events are not marked guest_attributed" \
  "echo '$EV' | J \"[e['guest_attributed'] for e in d['events'] if e['kind']=='tcp_connect']\" | grep -vq True"
check "the tap counters count the guest's traffic" \
  "api $U/api/v1/trace/tap | J \"d['rows'][0]['fromGuestBytes']>0 and d['rows'][0]['toGuestBytes']>0\" | grep -q True"

echo "== 3. isolation drops what is not allowed, and keeps what is"
R=$(api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate)
check "isolate is applied through tcx and names the tap" "echo '$R' | J \"d['applied'] and d['enforcement']=='tcx' and d['taps']==['vethh']\" | grep -q True"
sleep 1
check "allowed management address still reachable (IPv4)" "[ \"\$(code4 10.99.0.1)\" = 200 ]"
check "non-allowed address is dropped (IPv4)" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "allowed management address still reachable (IPv6)" "[ \"\$(code6 fd99::1)\" = 200 ]"
check "non-allowed address is dropped (IPv6)" "[ \"\$(code6 fd99::3)\" = 000 ]"
check "ping to the allowed address works, so ARP and ND still pass" "guest ping -c1 -W2 10.99.0.1 >/dev/null 2>&1"
check "ping to the non-allowed address is dropped" "! guest ping -c1 -W2 10.99.0.3 >/dev/null 2>&1"
sleep 1
EV=$(api "$U/api/v1/events")
check "the blocked connect attempt is an event marked blocked" \
  "echo '$EV' | J \"[e for e in d['events'] if e['kind']=='guest_connect' and e['dst']=='10.99.0.3' and e.get('blocked')][0]['blocked']\" | grep -q True"
T=$(api $U/api/v1/trace/tap)
check "the tap reports isolated with dropped packets" "echo '$T' | J \"d['rows'][0]['isolated'] and d['rows'][0]['droppedPackets']>0\" | grep -q True"
check "security shows enforcement tcx and the allow list" "api '$U/api/v1/security' | J \"d['enforcement']=='tcx' and '10.99.0.1/32' in d['allowList']\" | grep -q True"

echo "== 4. isolation survives a daemon restart (the links are pinned, so it is never open)"
stopd
start -isolate-allow 10.99.0.1/32,fd99::1/128
check "the restarted daemon reports the VM still isolated (it adopted the enforcement, it did not need to redo it)" \
  "api $U/api/v1/trace/tap | J \"[r['isolated'] for r in d['rows'] if r['vm']=='taptest'][0]\" | grep -q True"
check "the non-allowed address is still dropped after the restart" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "the allowed address is still reachable" "[ \"\$(code4 10.99.0.1)\" = 200 ]"

echo "== 5. release lifts it"
R=$(api -X POST -d '{"vm":"taptest"}' $U/api/v1/release)
check "release is applied" "echo '$R' | J \"d['applied'] and d['audit']['result']=='applied'\" | grep -q True"
sleep 1
check "the non-allowed address is reachable again" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
stopd
start -isolate-allow 10.99.0.1/32,fd99::1/128
check "a released VM is not re-isolated by a restart" "[ \"\$(code4 10.99.0.3)\" = 200 ]"

echo "== 8. enforcement outlives the daemon"
ALLOW="-isolate-allow 10.99.0.1/32,fd99::1/128"
mine() { sudo bpftool net 2>/dev/null | grep -E "^vethh" | grep -c shukra_tap; }
pins() { sudo sh -c 'ls /sys/fs/bpf/shukra/tap/link-* 2>/dev/null | wc -l'; }
api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
check "isolated before the crash: the non-allowed address is dropped" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "the kernel holds two links on the tap, and they are pinned" "[ \"\$(mine)\" = 2 ] && [ \"\$(pins)\" -ge 2 ]"
# A crash. No graceful shutdown runs, so nothing gets a chance to clean up.
sudo pkill -9 -f "$BIN -listen"; sleep 1
check "the daemon is really gone" "! pgrep -f '$BIN -listen' >/dev/null"
check "AFTER THE CRASH the VM is still cut off (fail closed)" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "after the crash the allowed management address is still reachable" "[ \"\$(code4 10.99.0.1)\" = 200 ]"
check "the links are still attached in the kernel" "[ \"\$(mine)\" = 2 ]"
start $ALLOW
check "the restarted daemon adopted the links: tap attached, and says it survives restarts" \
  "api $U/api/v1/programs | J \"[p['detail'] for p in d['programs'] if p['name']=='tap'][0]\" | grep -q 'survives a daemon restart'"
check "it reads the enforcement back from the kernel: the tap reports isolated" \
  "api $U/api/v1/trace/tap | J \"[r['isolated'] for r in d['rows'] if r['vm']=='taptest'][0]\" | grep -q True"
check "it did not need to re-apply anything" "! grep -q 'isolation re-applied' $D/daemon.log"
check "still cut off after the restart" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "still exactly two links: it adopted them instead of attaching a second pair" "[ \"\$(mine)\" = 2 ]"

R=$(api -X POST -d '{"vm":"taptest"}' $U/api/v1/release); sleep 1
check "release opens the VM" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
stopd
check "a graceful stop of a NOT isolated tap detaches everything: no link left on the VM" "[ \"\$(mine)\" = 0 ] && [ \"\$(pins)\" = 0 ]"
check "and the VM is reachable" "[ \"\$(code4 10.99.0.3)\" = 200 ]"

start $ALLOW
api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
check "isolated again" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
stopd
check "a graceful stop of an ISOLATED tap leaves it enforcing" "[ \"\$(code4 10.99.0.3)\" = 000 ] && [ \"\$(mine)\" = 2 ]"
check "and says so in the log" "grep -q 'left 1 isolated taps enforcing' $D/daemon.log"

# The kernel state is gone but the record still says isolated, as after a reboot: this
# is the case the daemon re-applies, from what it recorded.
sudo "$BIN" -detach-all >/dev/null
check "with the kernel state gone, the VM is open" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
start $ALLOW
check "the daemon re-applies the recorded isolation" "grep -q 'isolation re-applied for taptest' $D/daemon.log && [ \"\$(code4 10.99.0.3)\" = 000 ]"
stopd

OUT=$(sudo "$BIN" -detach-all -data-dir "$D/data")
check "detach-all reports what it removed" "echo '$OUT' | grep -q 'detached 2 tap links'"
check "detach-all records the release" "echo '$OUT' | grep -q 'recorded a release for 1 VMs'"
check "detach-all opens the VM with no daemon running" "[ \"\$(code4 10.99.0.3)\" = 200 ] && [ \"\$(mine)\" = 0 ] && [ \"\$(pins)\" = 0 ]"
start $ALLOW
check "a restart after detach-all does not isolate the VM again" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
# the daemon is left running for the sections that follow

echo "== 7. a real tun/tap: the host's own frames are not the guest's, and the guest's are"
# A veth's peer sits in a namespace. A tap is what QEMU really holds, and the kernel
# loops host-sent multicast back in through the device's ingress hook, where it must
# not be mistaken for a frame the guest sent.
sudo ip tuntap add dev tapx mode tap
sudo ip addr add 10.97.0.1/24 dev tapx; sudo ip -6 addr add fd97::1/64 dev tapx nodad; sudo ip link set tapx up
cat > "$D/holder.py" <<'PY'
import fcntl, os, struct, sys, time
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"tapx", 0x0002 | 0x1000))   # IFF_TAP | IFF_NO_PI
os.set_blocking(fd, False)
frame = bytes.fromhex("ffffffffffff" "020000000001" "0806") + bytes(28)     # a broadcast ARP-shaped frame, 42 bytes
sent = False
while True:
    try: os.read(fd, 2048)
    except BlockingIOError: pass
    if not sent and os.path.exists(sys.argv[1]):
        for _ in range(3): os.write(fd, frame)                              # the guest sends three frames
        sent = True
    time.sleep(0.05)
PY
sudo python3 "$D/holder.py" "$D/send-now" >/dev/null 2>&1 &
HOLDER=$!
bash -c "exec -a /usr/bin/qemu-system-x86_64 bash $D/loop.sh -name tunvm -uuid 7777 -netdev tap,id=n1,ifname=tapx,script=no" >/dev/null 2>&1 &
sleep 5
tapx() { api "$U/api/v1/trace/tap" | J "[r for r in d['rows'] if r['vm']=='tunvm'][0]['$1']"; }
check "the tap of a second VM is found and instrumented" "api $U/api/v1/vms | J \"[v['taps'] for v in d['vms'] if v['name']=='tunvm'][0]\" | grep -q tapx"
# Host-originated traffic on the tap: an ARP for a neighbour that does not exist, and
# IPv6 multicast, which the kernel loops back through ingress.
ping -c2 -W1 10.97.0.9 >/dev/null 2>&1
ping -6 -c2 -W1 -I tapx ff02::1 >/dev/null 2>&1
sleep 3
check "frames the host sent to the guest are counted as to_guest" "[ \"\$(tapx toGuestPackets)\" -gt 0 ]"
check "the host's own looped-back multicast is NOT counted as from the guest" "[ \"\$(tapx fromGuestPackets)\" = 0 ]"
touch "$D/send-now"; sleep 3
check "the three frames the guest really wrote are counted as from_guest" "[ \"\$(tapx fromGuestPackets)\" = 3 ]"
check "and their bytes: 3 x 42" "[ \"\$(tapx fromGuestBytes)\" = 126 ]"
sudo kill $HOLDER 2>/dev/null; sudo pkill -f "qemu-system-x86_64 .*tunvm"; sudo ip link del tapx 2>/dev/null

echo "== 6. the tap program comes off when the VM goes"
sudo pkill -f "qemu-system-x86_64 .*taptest"; sleep 6
check "the tap program is detached again with no VM" "api $U/api/v1/programs | J \"[p['status'] for p in d['programs'] if p['name']=='tap'][0]\" | grep -q detached"
stopd

echo; echo "passed $PASS, failed $FAILN"
[ $FAILN -eq 0 ]
