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
  sudo pkill -f "$BIN -listen" 2>/dev/null; sudo "$BIN" -detach-all >/dev/null 2>&1; sudo pkill -f "qemu-system-x86_64 .*(taptest|tunvm)" 2>/dev/null; sudo pkill -f "$D/holder.py" 2>/dev/null; sudo ip link del tapx 2>/dev/null; kill "$HTTP_PID" "$UDP_PID" 2>/dev/null
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

printf 'destinations:\n  - cidr: 10.99.0.3/32\n    name: watched-host\n    severity: high\nports:\n  - port: 5300\n    name: udp-watch\n    proto: udp\n  - port: 8090\n    name: guest-inbound-watch\n    dir: in\n  - port: 5311\n    name: response-enforce\n    proto: udp\n  - port: 5312\n    name: response-ask\n    proto: udp\ndns:\n  - name: dns-watch\n    suffix: watched.test\n    severity: high\ntls:\n  - name: tls-watch\n    suffix: watched.test\n    severity: high\nresponses:\n  - {name: rig-ask, action: isolate, rules: [response-ask]}\n  - {name: rig-auto, action: isolate, mode: enforce, rules: [response-enforce], release_after: 1m}\n' > $D/rules.yaml
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

echo "== 9. guest UDP: flows, rules, multicast, isolation"
# One listener per address, so "delivered" and "dropped" can be told apart.
cat > "$D/udpsrv.py" <<'PY'
import select, socket, sys
socks = {}
for spec in sys.argv[1:]:
    addr, port, path = spec.split(",")
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM); s.bind((addr, int(port))); socks[s] = path
while True:
    for s in select.select(list(socks), [], [])[0]:
        s.recvfrom(2048)
        open(socks[s], "a").write("x\n")
PY
for f in a4 b4 a6 b6; do : > "$D/udp-$f.log"; done
python3 "$D/udpsrv.py" "10.99.0.1,9999,$D/udp-a4.log" "10.99.0.3,9999,$D/udp-b4.log" "fd99::1,9999,$D/udp-a6.log" "fd99::3,9999,$D/udp-b6.log" >/dev/null 2>&1 &
UDP_PID=$!
sleep 1
usend() { guest python3 -c "
import socket,sys
addr,port,n,sport=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
s=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,socket.SOCK_DGRAM)
if sport: s.bind(('::' if ':' in addr else '0.0.0.0',sport))
for _ in range(n): s.sendto(b'hello',(addr,port))
" "$@"; }
recvd() { wc -l < "$D/udp-$1.log" | tr -d ' '; }
udpev() { api "$U/api/v1/events" | J "len([e for e in d['events'] if e['kind']=='guest_flow' and e.get('dst')=='$1' and e.get('dport')==$2 ${3:-}])"; }

FROM0=$(api "$U/api/v1/trace/tap" | J "[r['fromGuestPackets'] for r in d['rows'] if r['vm']=='taptest'][0]")
usend 10.99.0.1 9999 20 40000; sleep 1
check "the datagrams are delivered (a monitor drops nothing)" "[ \"\$(recvd a4)\" = 20 ]"
check "20 back-to-back datagrams on one flow are ONE event, not twenty" "[ \"\$(udpev 10.99.0.1 9999)\" = 1 ]"
check "the event names the VM, the guest's address, the protocol and the tap, and is guest-attributed" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['attribution']=='guest-tap' and e['vm']['name']=='taptest' and e.get('proto')=='udp' and e.get('src')=='10.99.0.2' and e.get('iface')=='vethh' and e['dport']==9999 for e in d['events'] if e['kind']=='guest_flow' and e.get('dst')=='10.99.0.1')\" | grep -q True"
usend 10.99.0.1 9999 1 40001; sleep 1
check "a new source port is a new flow: a second event" "[ \"\$(udpev 10.99.0.1 9999)\" = 2 ]"

# The guest needs a route for multicast, or the send fails before it reaches the tap and
# this check would pass on earlier traffic without testing anything.
sudo ip -n g1 route add 224.0.0.0/4 dev vethg 2>/dev/null
FROM0=$(api "$U/api/v1/trace/tap" | J "[r['fromGuestPackets'] for r in d['rows'] if r['vm']=='taptest'][0]")
usend 224.0.0.251 5353 3 0; sleep 1
FROM1=$(api "$U/api/v1/trace/tap" | J "[r['fromGuestPackets'] for r in d['rows'] if r['vm']=='taptest'][0]")
check "multicast is counted in the tap's packets (three more, and only those)" "[ \"$FROM1\" = \"\$((FROM0+3))\" ]"
check "but multicast produces no event" "[ \"\$(udpev 224.0.0.251 5353)\" = 0 ]"

usend fd99::1 9999 5 41000; sleep 1
check "an IPv6 UDP flow is one event with the IPv6 destination" "[ \"\$(udpev fd99::1 9999)\" = 1 ] && [ \"\$(recvd a6)\" = 5 ]"

usend 10.99.0.3 9999 1 41100; sleep 1
check "a destination rule fires on UDP to a watched address, guest-attributed, protocol udp" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e.get('proto')=='udp' and e['vm']['name']=='taptest' for e in d['events'] if e['kind']=='detection' and e.get('rule')=='watched-host')\" | grep -q True"
usend 10.99.0.1 5300 1 41200; sleep 1
check "a proto: udp port rule fires on UDP, and says udp" \
  "api $U/api/v1/events | J \"any('(udp)' in e['message'] and e['guest_attributed'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='udp-watch')\" | grep -q True"
usend 10.99.0.1 5301 1 41300; sleep 1
check "a UDP flow to a port with no rule raises no detection for it" \
  "api $U/api/v1/events | J \"[e for e in d['events'] if e['kind']=='detection' and '5301' in e.get('message','')]\" | grep -q '\[\]'"

api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
B4=$(recvd b4); A4=$(recvd a4); B6=$(recvd b6); A6=$(recvd a6)
usend 10.99.0.3 9999 3 42000; usend 10.99.0.1 9999 3 42001; usend fd99::3 9999 3 42002; usend fd99::1 9999 3 42003; sleep 1
check "isolated: UDP to the allowed IPv4 address is still delivered" "[ \"\$(recvd a4)\" = \"\$((A4+3))\" ]"
check "isolated: UDP to a non-allowed IPv4 address is dropped" "[ \"\$(recvd b4)\" = \"$B4\" ]"
check "isolated: UDP to the allowed IPv6 address is still delivered" "[ \"\$(recvd a6)\" = \"\$((A6+3))\" ]"
check "isolated: UDP to a non-allowed IPv6 address is dropped" "[ \"\$(recvd b6)\" = \"$B6\" ]"
check "the dropped flow is an event marked blocked" "[ \"\$(udpev 10.99.0.3 9999 \"and e.get('blocked')\")\" -ge 1 ]"
check "and the allowed flow is not marked blocked" "[ \"\$(udpev 10.99.0.1 9999 \"and e.get('blocked')\")\" = 0 ]"
api -X POST -d '{"vm":"taptest"}' $U/api/v1/release >/dev/null; sleep 1
usend 10.99.0.3 9999 2 42100; sleep 1
check "released: UDP to that address is delivered again" "[ \"\$(recvd b4)\" = \"\$((B4+2))\" ]"
kill $UDP_PID 2>/dev/null

echo "== 10. drops: what the kernel dropped on the tap, and whose it was"
# Shukra's own drops are TC_INGRESS in the kernel's eyes. So the kernel's count minus what the tap program
# says it dropped is what something ELSE dropped, and a real tc filter on the tap is that something.
dtap() { api "$U/api/v1/trace/drops" | J "[t for t in d['taps'] if t['tap']=='vethh'][0]['$1']"; }
check "the drops program is attached" "api $U/api/v1/programs | J \"[p['status'] for p in d['programs'] if p['name']=='drops'][0]\" | grep -q attached"
check "the tap is listed, for its VM, with nothing invented" "api $U/api/v1/trace/drops | J \"[t['vm'] for t in d['taps'] if t['tap']=='vethh'][0]\" | grep -q taptest"
OTHER0=$(dtap otherDrops); SHUK0=$(dtap shukraDropped)

# Something else drops the guest's packets: a real tc filter on the tap, nothing to do with Shukra.
# TCX may already have created the clsact qdisc, so an existing one is fine, and only the filter is
# removed afterwards: deleting the qdisc could take Shukra's own links with it.
sudo tc qdisc add dev vethh clsact 2>/dev/null || true
# The filter drops every frame on the tap, ARP included. If the guest had to ask who has 10.99.0.1 while it is
# on, the answer could never come and most pings would never leave the guest, so the entry is made permanent
# first and only frames the guest really sends are counted.
guest ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1
HOSTMAC=$(sudo ip -n g1 neigh show 10.99.0.1 | awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1)}' | head -1)
sudo ip -n g1 neigh replace 10.99.0.1 lladdr "$HOSTMAC" dev vethg nud permanent
tcin() { api "$U/api/v1/trace/drops" | J "sum(r['count'] for r in d['rows'] if r['tap']=='vethh' and r['reason']=='TC_INGRESS')"; }
TC0=$(tcin)
sudo tc filter add dev vethh ingress matchall action drop
check "the filter is really on the tap" "sudo tc filter show dev vethh ingress | grep -q matchall"
SENT=$(guest ping -c 20 -i 0.05 -W 1 10.99.0.1 2>&1 | sed -n 's/^\([0-9]*\) packets transmitted.*/\1/p'); sleep 1
OTHER1=$(dtap otherDrops); SHUK1=$(dtap shukraDropped); TC1=$(tcin)
sudo tc filter del dev vethh ingress
sudo ip -n g1 neigh del 10.99.0.1 dev vethg 2>/dev/null
echo "  ping sent ${SENT:-?}; the kernel's TC_INGRESS on the tap rose $TC0 -> $TC1; otherDrops $OTHER0 -> $OTHER1; Shukra's own $SHUK0 -> $SHUK1"
check "Shukra's own programs are still on the tap after the filter is gone" "sudo bpftool net show dev vethh 2>/dev/null | grep -q shukra_tap_from_guest"
check "twenty pings were sent, and every one the tc filter dropped is the kernel's TC_INGRESS on that tap (rose by at least twenty: $TC0 -> $TC1)" "[ \"${SENT:-0}\" = 20 ] && [ $((TC1-TC0)) -ge 20 ]"
check "they are 'other', not Shukra's: otherDrops rose by at least twenty ($OTHER0 -> $OTHER1)" "[ $((OTHER1-OTHER0)) -ge 20 ]"
check "and Shukra says it dropped none of them ($SHUK0 -> $SHUK1)" "[ $SHUK1 -eq $SHUK0 ]"
check "doctor names the VM and the tap" "api $U/api/v1/doctor | J \"any(c['id']=='vm-drops-not-shukra' and 'taptest (vethh' in c['detail'] for c in d['checks'])\" | grep -q True"
check "the drops are on /metrics with the kernel's reason" "api $U/metrics | grep -q 'shukra_tap_kernel_drops_total{vm=\"taptest\",tap=\"vethh\",reason=\"TC_INGRESS\"}'"
check "the kernel function that dropped them is named or shown as an address" "api $U/api/v1/trace/drops | J \"[r['location'] for r in d['rows'] if r['tap']=='vethh' and r['reason']=='TC_INGRESS'][0]\" | grep -qE '.+'"

# Shukra's own isolation is the same kernel reason, and must NOT be blamed on anyone else.
api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
OTHER2=$(dtap otherDrops); SHUK2=$(dtap shukraDropped)
guest ping -c 20 -i 0.05 -W 1 10.99.0.3 >/dev/null 2>&1; sleep 1
OTHER3=$(dtap otherDrops); SHUK3=$(dtap shukraDropped)
api -X POST -d '{"vm":"taptest"}' $U/api/v1/release >/dev/null; sleep 1
check "isolation dropped the pings: Shukra's own count rose by at least twenty ($SHUK2 -> $SHUK3)" "[ $((SHUK3-SHUK2)) -ge 20 ]"
check "and they are not blamed on another program: otherDrops did not move ($OTHER2 -> $OTHER3)" "[ $((OTHER3-OTHER2)) -le 3 ]"

echo "== 11. TCP handshake outcomes, both ways, with exact counts"
# One helper opens a connection and closes it: to an open port the handshake completes, to a closed port the
# peer answers RST, and to a port that drops the SYN nobody answers at all. Every attempt must be exactly one of
# accepted, refused, timed out or blocked, and a repeat of the same SYN is a retransmit and not an attempt.
gconn() { guest python3 -c "import socket,sys;s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET);s.settimeout(float(sys.argv[3]));s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close()" "$@"; }
hconn() { python3 -c "import socket,sys;s=socket.socket();s.settimeout(float(sys.argv[3]));s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close()" "$@"; }
oc() { api "$U/api/v1/trace/tap" | J "[r for r in d['rows'] if r['tap']=='vethh'][0]['$1']"; }
FIELDS="outSyn outAccepted outRefused outTimedOut outRetransmits outBlocked inSyn inAccepted inRefused inIgnored"
snapoc() { for f in $FIELDS; do echo "$1_$f=$(oc $f)"; done; }
# a listener inside the guest, and a host rule and a guest rule that silently drop one port each
( cd "$D" && exec sudo ip netns exec g1 python3 -m http.server 8090 --bind 0.0.0.0 >/dev/null 2>&1 ) &
GLIS=$!
sudo iptables -I INPUT -d 10.99.0.1 -p tcp --dport 8081 -j DROP
sudo ip netns exec g1 iptables -I INPUT -p tcp --dport 8092 -j DROP
sleep 5; oc outSyn >/dev/null   # let anything pending from earlier sections age out and be counted
eval "$(snapoc B)"

for i in 1 2 3; do gconn 10.99.0.1 8080 1; done          # open port: accepted x3
for i in 1 2 3 4; do gconn 10.99.0.1 9 1; done           # closed port: refused x4
for i in 1 2; do gconn fd99::1 8080 1; done              # IPv6 open: accepted x2
gconn fd99::1 9 1                                         # IPv6 closed: refused x1
gconn 10.99.0.1 8090 1                                    # the guest's OWN connect to the port the inbound rule watches: refused x1
for i in 1 2 3; do gconn 10.99.0.1 8081 0.5; done        # the host drops the SYN: never answered x3
gconn 10.99.0.1 8081 1.6                                  # ... held long enough for one retransmit
api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
for i in 1 2; do gconn 10.99.0.3 8080 0.5; done          # isolation drops the SYN: blocked x2
api -X POST -d '{"vm":"taptest"}' $U/api/v1/release >/dev/null; sleep 1
for i in 1 2 3; do hconn 10.99.0.2 8090 1; done          # into the guest, listening: accepted x3
for i in 1 2; do hconn 10.99.0.2 8091 1; done            # into the guest, closed: refused x2
for i in 1 2; do hconn 10.99.0.2 8092 0.5; done          # into the guest, dropped: ignored x2
sleep 5                                                   # more than the 3 s a SYN waits for an answer
eval "$(snapoc A)"
d() { echo $(( A_$1 - B_$1 )); }
echo "  out: attempts $(d outSyn) = accepted $(d outAccepted) + refused $(d outRefused) + never answered $(d outTimedOut) + blocked $(d outBlocked)   retransmits $(d outRetransmits)"
echo "  in:  attempts $(d inSyn) = accepted $(d inAccepted) + refused $(d inRefused) + ignored $(d inIgnored)"
check "outbound: 5 connections were accepted (IPv4 and IPv6)" "[ \"\$(d outAccepted)\" = 5 ]"
check "outbound: 6 were refused, by an RST (IPv4 and IPv6)" "[ \"\$(d outRefused)\" = 6 ]"
check "outbound: the 4 SYNs nobody answered were counted as never answered" "[ \"\$(d outTimedOut)\" = 4 ]"
check "outbound: the 2 SYNs isolation dropped are blocked, and are not also timeouts" "[ \"\$(d outBlocked)\" = 2 ]"
check "outbound: the repeated SYN is one retransmit and not a new attempt" "[ \"\$(d outRetransmits)\" = 1 ]"
check "outbound: attempts are exactly accepted + refused + never answered + blocked (17)" "[ \"\$(d outSyn)\" = 17 ] && [ \$(( $(d outAccepted) + $(d outRefused) + $(d outTimedOut) + $(d outBlocked) )) = 17 ]"
check "inbound: 3 connections into the guest were accepted" "[ \"\$(d inAccepted)\" = 3 ]"
check "inbound: 2 were refused by the guest's RST" "[ \"\$(d inRefused)\" = 2 ]"
check "inbound: 2 SYNs the guest ignored were counted as ignored" "[ \"\$(d inIgnored)\" = 2 ]"
check "inbound: attempts are exactly accepted + refused + ignored (7)" "[ \"\$(d inSyn)\" = 7 ]"
check "each accepted outbound connection is in the handshake histogram, and it is fast on a veth" "api $U/api/v1/trace/tap | J \"[(sum(r['handshakeHist']), r['outAccepted'], r['handshakeP99Ns']) for r in d['rows'] if r['tap']=='vethh'][0]\" | awk -F'[(), ]+' '\$2==\$3 && \$4<100000000{f=1} END{exit !f}'"
check "a connection made into the guest is a guest_inbound event naming the peer and the guest, guest-attributed" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['attribution']=='guest-tap' and e['vm']['name']=='taptest' and e.get('src')=='10.99.0.1' and e.get('dst')=='10.99.0.2' and e['dport']==8090 and e.get('proto')=='tcp' for e in d['events'] if e['kind']=='guest_inbound')\" | grep -q True"
check "one event per inbound connection: 3 to 8090, 2 to 8091, 2 to 8092" "api $U/api/v1/events | J \"[sum(1 for e in d['events'] if e['kind']=='guest_inbound' and e['dport']==p) for p in (8090,8091,8092)]\" | grep -q '\[3, 2, 2\]'"
check "an inbound port rule fires on the guest port, naming the peer" "api $U/api/v1/events | J \"any(e['guest_attributed'] and 'connected in from 10.99.0.1' in e['message'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='guest-inbound-watch')\" | grep -q True"
check "the guest's own connect to that same port did happen, and the inbound rule did not fire on it" "api $U/api/v1/events | J \"any(e['kind']=='guest_connect' and e['dport']==8090 and e.get('dst')=='10.99.0.1' for e in d['events'])\" | grep -q True && api $U/api/v1/events | J \"[e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='guest-inbound-watch' and 'connected in' not in e['message']]\" | grep -q '\[\]'"
check "the outcomes are on /metrics" "api $U/metrics | grep -q 'shukra_tap_connect_outcomes_total{vm=\"taptest\",tap=\"vethh\",direction=\"out\",result=\"refused\"}'"
sudo iptables -D INPUT -d 10.99.0.1 -p tcp --dport 8081 -j DROP 2>/dev/null
sudo ip netns exec g1 iptables -D INPUT -p tcp --dport 8092 -j DROP 2>/dev/null
kill $GLIS 2>/dev/null; sudo pkill -f 'http.server 8090' 2>/dev/null

echo "== 12. guest DNS names"
# The program only recognises a plain query and copies its question; the name is decoded in the daemon. Queries are
# built by hand and sent where nothing answers, since only what the guest asks matters.
cat > "$D/dnsq.py" <<'PY'
import socket, sys
# dnsq.py DST NAME QTYPE COUNT [RAW-HEX]: RAW-HEX replaces the question, to send something malformed
dst, name, qtype, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
q = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
if len(sys.argv) > 5:
    q += bytes.fromhex(sys.argv[5])
else:
    for l in name.split("."):
        q += bytes([len(l)]) + l.encode()
    q += bytes([0]) + qtype.to_bytes(2, "big") + bytes([0, 1])
s = socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(n):
    s.sendto(q, (dst, 53))
PY
dq() { guest python3 "$D/dnsq.py" "$@"; sleep 1; }
dnsn() { api "$U/api/v1/events" | J "len([e for e in d['events'] if e['kind']=='guest_dns' and e['dns_name']=='$1' and e.get('qtype','')=='$2'])"; }
dnsall() { api "$U/api/v1/events" | J "len([e for e in d['events'] if e['kind']=='guest_dns'])"; }

dq 10.99.0.1 WwW.ExAmPlE.CoM 1 3
check "three lookups of a name in mixed case are ONE event, lower-cased, type A" "[ \"\$(dnsn www.example.com A)\" = 1 ]"
check "it names the VM, the guest's address, the resolver, the tap, udp and port 53, and is guest-attributed" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['attribution']=='guest-tap' and e['vm']['name']=='taptest' and e.get('proto')=='udp' and e.get('src')=='10.99.0.2' and e.get('dst')=='10.99.0.1' and e.get('iface')=='vethh' and e['dport']==53 and not e.get('blocked') and not e.get('dns_truncated') for e in d['events'] if e['kind']=='guest_dns' and e['dns_name']=='www.example.com')\" | grep -q True"
dq 10.99.0.1 www.example.com 1 2
check "the same name again inside the minute is not announced again" "[ \"\$(dnsn www.example.com A)\" = 1 ]"
dq 10.99.0.1 www.example.com 28 1
check "the same name with another type is its own event (AAAA)" "[ \"\$(dnsn www.example.com AAAA)\" = 1 ]"
dq fd99::1 v6.example.com 1 1
check "a query over IPv6 is an event with the IPv6 addresses" "api $U/api/v1/events | J \"any(e['src']=='fd99::2' and e['dst']=='fd99::1' for e in d['events'] if e['kind']=='guest_dns' and e['dns_name']=='v6.example.com')\" | grep -q True"
check "the flow to port 53 is still its own guest_flow event: names add to the flow, they do not replace it" "[ \"\$(udpev 10.99.0.1 53)\" -ge 1 ]"

L63=$(python3 -c "print('a'*63)")
dq 10.99.0.1 "$L63.$L63.$L63.test" 1 1
check "a name too long for the copy is an event that says it is cut short, with no type invented" \
  "api $U/api/v1/events | J \"any(e.get('dns_truncated') and e['dns_name'].startswith('aaaa') and not e.get('qtype') for e in d['events'] if e['kind']=='guest_dns')\" | grep -q True"

N0=$(dnsall)
dq 10.99.0.1 x 1 1 c00c00010001
guest python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'this is not a dns query at all', ('10.99.0.1',53))
s.sendto(bytes([0x12,0x34,0x81,0x80,0,1,0,0,0,0,0,0,1,ord('r'),0,0,1,0,1]),('10.99.0.1',53))   # a response, QR=1
s.sendto(bytes([0x12,0x34,1,0,0,2,0,0,0,0,0,0,1,ord('q'),0,0,1,0,1]),('10.99.0.1',53))          # two questions
"; sleep 1
check "a compression pointer, a non-DNS payload, a response and a two-question packet each produce no event" "[ \"\$(dnsall)\" = \"$N0\" ]"

dq 10.99.0.1 c2.watched.test 1 1
dq 10.99.0.1 quiet.example.org 1 1
check "a dns rule fires on the name, guest-attributed, and names it" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['vm']['name']=='taptest' and 'c2.watched.test' in e['message'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='dns-watch')\" | grep -q True"
check "and only on the names it matches" "api $U/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='dns-watch'])\" | grep -q '^1$'"

api -X POST -d '{"vm":"taptest"}' $U/api/v1/isolate >/dev/null; sleep 1
dq 10.99.0.3 blocked.example.com 1 1
check "a query isolation dropped is still an event, marked blocked" "api $U/api/v1/events | J \"any(e.get('blocked') for e in d['events'] if e['kind']=='guest_dns' and e['dns_name']=='blocked.example.com')\" | grep -q True"
api -X POST -d '{"vm":"taptest"}' $U/api/v1/release >/dev/null; sleep 1

# The switch lives in a pinned map, so the daemon sets it on every start, whatever a previous run left there.
stopd; start -isolate-allow 10.99.0.1/32,fd99::1/128 -dns-events=false
dq 10.99.0.1 private.example.com 1 1
check "-dns-events=false: the name is not recorded at all" "[ \"\$(dnsn private.example.com A)\" = 0 ]"
check "but the flow to port 53 still is (the program is running, it just does not read DNS)" "[ \"\$(udpev 10.99.0.1 53)\" -ge 1 ]"
stopd; start -isolate-allow 10.99.0.1/32,fd99::1/128
dq 10.99.0.1 public.example.com 1 1
check "and starting again without the flag turns names back on, whatever the last run left in the map" "[ \"\$(dnsn public.example.com A)\" = 1 ]"

echo "== 14. guest TLS server names"
# The program recognises the first segment of a ClientHello (handshake record, type 1) and copies it; the name, the
# protocols and the fingerprint are decoded in the daemon. Real hellos come from openssl, the odd ones are built by hand.
# The listener is the plain HTTP server: it accepts the connection, which is all a hello needs.
tls() { guest timeout 5 openssl s_client -connect "$1" -servername "$2" "${@:3}" </dev/null >/dev/null 2>&1; sleep 1; }
tlsn() { api "$U/api/v1/events" | J "len([e for e in d['events'] if e['kind']=='guest_tls' and e.get('sni','')=='$1'])"; }
tlsall() { api "$U/api/v1/events" | J "len([e for e in d['events'] if e['kind']=='guest_tls'])"; }
cat > "$D/hello.py" <<'PY'
import socket, struct, sys
# hello.py DST PORT NAME PAD: a ClientHello with the name first and PAD bytes of a padding extension after it
dst, port, name, pad = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), int(sys.argv[4])
def ext(t, d): return struct.pack(">HH", t, len(d)) + d
exts = ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
if pad: exts += ext(21, b"\0" * pad)
body = b"\x03\x03" + b"\0" * 32 + b"\0" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
hs = b"\x01" + len(body).to_bytes(3, "big") + body
rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
s = socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET)
s.settimeout(3)
s.connect((dst, port))
s.sendall(rec)
PY

tls 10.99.0.1:8080 WwW.ExAmPlE.CoM -alpn h2,http/1.1
check "a real ClientHello is ONE event with the name lower-cased" "[ \"\$(tlsn www.example.com)\" = 1 ]"
check "it names the VM, the guest and the server, the tap and the port, and is guest-attributed" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['attribution']=='guest-tap' and e['vm']['name']=='taptest' and e.get('proto')=='tcp' and e.get('src')=='10.99.0.2' and e.get('dst')=='10.99.0.1' and e.get('iface')=='vethh' and e['dport']==8080 and not e.get('blocked') and not e.get('tls_truncated') for e in d['events'] if e['kind']=='guest_tls' and e['sni']=='www.example.com')\" | grep -q True"
check "it carries the protocols offered, the highest TLS version, and a 32-hex JA3" \
  "api $U/api/v1/events | J \"any(e.get('alpn')=='h2,http/1.1' and e.get('tls_version')=='1.3' and len(e.get('ja3',''))==32 and not e.get('ech') for e in d['events'] if e['kind']=='guest_tls' and e['sni']=='www.example.com')\" | grep -q True"
tls 10.99.0.1:8080 www.example.com -alpn h2,http/1.1
check "each connection is its own event (a hello is not announced by name)" "[ \"\$(tlsn www.example.com)\" = 2 ]"
check "and the same client library has the same fingerprint both times" \
  "api $U/api/v1/events | J \"len(set(e['ja3'] for e in d['events'] if e['kind']=='guest_tls' and e.get('sni')=='www.example.com'))\" | grep -q '^1$'"
check "the flow it belongs to is still its own guest_connect event" "api $U/api/v1/events | J \"any(e['dport']==8080 and e.get('dst')=='10.99.0.1' for e in d['events'] if e['kind']=='guest_connect')\" | grep -q True"
tls "[fd99::1]:8080" v6.example.com
check "a hello over IPv6 is an event with the IPv6 addresses" "api $U/api/v1/events | J \"any(e['src']=='fd99::2' and e['dst']=='fd99::1' for e in d['events'] if e['kind']=='guest_tls' and e.get('sni')=='v6.example.com')\" | grep -q True"
guest timeout 5 openssl s_client -connect 10.99.0.1:8080 -noservername </dev/null >/dev/null 2>&1; sleep 1
check "a hello with no name is an event with none: it is what a client that hides where it goes looks like" \
  "api $U/api/v1/events | J \"any(not e.get('sni') and e.get('tls_version')=='1.3' and len(e.get('ja3',''))==32 for e in d['events'] if e['kind']=='guest_tls')\" | grep -q True"

N0=$(tlsall)
guest curl -s -m 2 -o /dev/null http://10.99.0.1:8080/
guest python3 -c "
import socket
s=socket.create_connection(('10.99.0.1',8080),timeout=3)
s.sendall(bytes([0x16,3,3,0,5,2,0,0,1,0]))       # a handshake record, but a ServerHello
s.sendall(bytes([0x17,3,3,0,5,1,2,3,4,5]))       # application data
"; sleep 1
check "plain HTTP, a ServerHello and application data each produce no event" "[ \"\$(tlsall)\" = \"$N0\" ]"

L=$(python3 -c "print('.'.join(['b'*60]*3) + '.example.org')")
guest python3 "$D/hello.py" 10.99.0.1 8080 "$L" 0; sleep 1
check "a long name (194 characters) is kept whole" "[ \"\$(tlsn $L)\" = 1 ]"
guest python3 "$D/hello.py" 10.99.0.1 8080 big.example.com 1800; sleep 1
check "a hello longer than the copy keeps its name, says it is cut short, and has no fingerprint" \
  "api $U/api/v1/events | J \"any(e.get('tls_truncated') and not e.get('ja3') for e in d['events'] if e['kind']=='guest_tls' and e.get('sni')=='big.example.com')\" | grep -q True"

tls 10.99.0.1:8080 c2.watched.test
tls 10.99.0.1:8080 quiet.example.org
check "a tls rule fires on the name, guest-attributed, and names it" \
  "api $U/api/v1/events | J \"any(e['guest_attributed'] and e['vm']['name']=='taptest' and 'c2.watched.test' in e['message'] for e in d['events'] if e['kind']=='detection' and e.get('rule')=='tls-watch')\" | grep -q True"
check "and only on the names it matches" "api $U/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='tls-watch'])\" | grep -q '^1$'"
check "and the dns rule for the same suffix did not judge the TLS name (it still has its one detection, from the lookup)" "api $U/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='detection' and e.get('rule')=='dns-watch'])\" | grep -q '^1$'"

# The switch lives in a pinned map, so the daemon sets it on every start, whatever a previous run left there.
stopd; start -isolate-allow 10.99.0.1/32,fd99::1/128 -tls-events=false
tls 10.99.0.1:8080 private.example.com
check "-tls-events=false: the name is not recorded at all" "[ \"\$(tlsn private.example.com)\" = 0 ]"
check "but the connection still is (the program is running, it just does not read the payload)" "api $U/api/v1/events | J \"len([e for e in d['events'] if e['kind']=='guest_connect' and e['dport']==8080])\" | grep -qv '^0$'"
stopd; start -isolate-allow 10.99.0.1/32,fd99::1/128
tls 10.99.0.1:8080 public.example.com
check "and starting again without the flag turns names back on, whatever the last run left in the map" "[ \"\$(tlsn public.example.com)\" = 1 ]"

echo "== 13. responses: a proposal changes nothing until a person approves it, and an enforced one acts and releases itself"
# Two trigger ports used only here (5312 is answered by a response that proposes, 5311 by one that enforces), so no
# earlier section can set them off. The non-allowed address 10.99.0.3 is reachable until the VM is isolated.
check "before anything, the guest can reach the address isolation would cut off" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
usend 10.99.0.1 5312 1 43000; sleep 3
check "a detection that a proposing response answers is a pending proposal" "api $U/api/v1/actions | J \"[(a['status'], a['vm'], a['mode']) for a in d['actions']]\" | grep -q \"('pending', 'taptest', 'propose')\""
check "and a proposal changes nothing: the VM is still reachable" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
check "it was announced as a detection a person can see, naming the command that approves it" "api $U/api/v1/events | J \"any(e.get('rule')=='action-proposed' and 'shukractl approve' in e['message'] for e in d['events'] if e['kind']=='detection')\" | grep -q True"
AID=$(api $U/api/v1/actions | J "d['actions'][0]['id']")
check "it holds the incident bundle it was made on" "api $U/api/v1/actions/$AID/incident | J \"d['vm']\" | grep -q taptest"
check "a read-only-style request without the key is refused, and nothing was decided" "[ \"\$(curl -s -o /dev/null -w %{http_code} -X POST $U/api/v1/actions/$AID/approve)\" = 401 ] && [ \"\$(code4 10.99.0.3)\" = 200 ]"
api -X POST -H "X-Shukra-Actor: rig" $U/api/v1/actions/$AID/approve >/dev/null; sleep 2
check "approved: the VM is cut off" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "the isolate record says who approved which action" "api $U/api/v1/isolations | J \"any('approved by rig' in i['audit']['actor'] and '$AID' in i['audit']['actor'] for i in d['isolations'])\" | grep -q True"
check "a decided proposal cannot be decided again" "[ \"\$(curl -s -o /dev/null -w %{http_code} -X POST -H \"$A\" $U/api/v1/actions/$AID/approve)\" = 409 ]"
api -X POST -d '{"vm":"taptest"}' $U/api/v1/release >/dev/null; sleep 2
check "released by a person: reachable again" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
usend 10.99.0.1 5311 1 43100; sleep 3
check "an enforcing response cuts the VM off at once, with nobody deciding" "[ \"\$(code4 10.99.0.3)\" = 000 ]"
check "and says so: an executed action with a release time, decided by the response itself" "api $U/api/v1/actions?all=1 | J \"[(a['status'], a['decidedBy'].startswith('auto:rig-auto:'), bool(a.get('releaseAt'))) for a in d['actions'] if a['mode']=='enforce'][0]\" | grep -q \"('executed', True, True)\""
echo "  waiting for the release timer (one minute, checked every five seconds)"
for _ in $(seq 1 20); do [ "$(code4 10.99.0.3)" = 200 ] && break; sleep 5; done
check "the response released the VM again by itself when its time came" "[ \"\$(code4 10.99.0.3)\" = 200 ]"
check "and the action says so" "api $U/api/v1/actions?all=1 | J \"[a['status'] for a in d['actions'] if a['mode']=='enforce'][0]\" | grep -q released"

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
