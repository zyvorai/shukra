#!/usr/bin/env bash
# bench-tap.sh OBJECT [OBJECT...]: what the tap program costs per packet, measured on this kernel.
#
# Each object is loaded as a private copy, in its own mount namespace with a fresh bpffs, so it has maps of its
# own, is attached to nothing, and cannot touch what a running shukrad has pinned or any tap. It is timed with
# BPF_PROG_TEST_RUN on synthetic packets: no traffic, no VM, safe on a production host. Give it two objects (the
# program before a change and after it) to see what the change costs; an object that has the TLS switch
# (tls_cfg) is run with it on and with it off.
#
#   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpf -c bpf/tap.bpf.c -o /tmp/tap_new.o   # bpf/vmlinux.h comes from `make generate`
#   git show main:bpf/tap.bpf.c > /tmp/tap_old.bpf.c   # and compile that the same way
#   sudo scripts/bench-tap.sh /tmp/tap_old.o /tmp/tap_new.o
#
# Read the numbers as a floor: the same packet is run two million times, so the caches are as warm as they
# will ever be. The difference between two objects is the honest part. Needs root, bpftool, python3, unshare.
set -euo pipefail
[ $# -ge 1 ] || { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
REPEAT="${REPEAT:-2000000}"
W="$(mktemp -d /tmp/shukra-bench.XXXXXX)"
trap 'rm -rf "$W"' EXIT

# Packets: a full data segment, an application-data record, a bare ACK, a ClientHello, and a UDP datagram.
python3 - "$W" <<'PY'
import struct, sys
w = sys.argv[1]
def eth(): return bytes([2,0,0,0,0,1, 2,0,0,0,0,2]) + struct.pack(">H", 0x0800)
def ip(proto, n): return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + n, 1, 0x4000, 64, proto, 0, bytes([10,0,0,5]), bytes([203,0,113,9]))
def tcp(payload, flags=0x18):
    t = struct.pack(">HHIIBBHHH", 40000, 443, 1000, 2000, 5 << 4, flags, 65535, 0, 0) + payload
    return eth() + ip(6, len(t)) + t
def ext(t, d): return struct.pack(">HH", t, len(d)) + d
name = b"bench.example.com"
exts = ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name) + ext(16, struct.pack(">HB", 3, 2) + b"h2") + ext(43, bytes([2, 3, 4]))
body = bytes([3, 3]) + bytes(32) + bytes([0]) + struct.pack(">H", 4) + bytes([0x13, 1, 0x13, 2]) + bytes([1, 0]) + struct.pack(">H", len(exts)) + exts
hs = bytes([1]) + len(body).to_bytes(3, "big") + body
hello = bytes([0x16, 3, 1]) + struct.pack(">H", len(hs)) + hs
data = bytes([0xaa]) + bytes((i * 131 + 7) & 0xff for i in range(1, 1448))
app = bytes([0x17, 3, 3, 0x05, 0xa0]) + data[5:]
u = struct.pack(">HHHH", 40000, 9999, 108, 0) + bytes(100)
pk = {"data": tcp(data), "appdata": tcp(app), "ack": tcp(b"", 0x10), "hello": tcp(hello), "udp": eth() + ip(17, len(u)) + u}
for k, v in pk.items():
    open(f"{w}/pkt_{k}", "wb").write(v)
PY

cat > "$W/one.sh" <<'EOS'
set -euo pipefail
obj=$1; label=$2; switch=$3; W=$4; REPEAT=$5
mount --make-rprivate / 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf
bpftool prog loadall "$obj" /sys/fs/bpf/p >/dev/null
prog=$(ls /sys/fs/bpf/p | grep -i from_guest | head -1)
[ -n "$prog" ] || { echo "$obj has no from_guest program"; exit 1; }
if [ "$switch" = off ]; then bpftool map update pinned /sys/fs/bpf/tls_cfg key 0 0 0 0 value 1 0 0 0; fi
for pkt in data appdata ack hello udp; do
  runs=""
  for _ in 1 2 3 4 5; do
    ns=$(bpftool prog run pinned "/sys/fs/bpf/p/$prog" data_in "$W/pkt_$pkt" repeat "$REPEAT" 2>&1 | grep -oE 'duration[^0-9]*[0-9]+' | grep -oE '[0-9]+$')
    runs="$runs $ns"
  done
  med=$(echo $runs | tr ' ' '\n' | sort -n | sed -n 3p)
  printf "%-26s %-8s %5s ns/packet   (runs:%s)\n" "$label" "$pkt" "$med" "$runs"
done
EOS

printf "%-26s %-8s %s\n" "program" "packet" "median of 5 runs of $REPEAT"
for obj in "$@"; do
  label=$(basename "$obj" .o)
  if grep -aq 'tls_cfg' "$obj"; then
    unshare -m bash "$W/one.sh" "$obj" "$label (tls on)" on "$W" "$REPEAT"
    unshare -m bash "$W/one.sh" "$obj" "$label (tls off)" off "$W" "$REPEAT"
  else
    unshare -m bash "$W/one.sh" "$obj" "$label" on "$W" "$REPEAT"
  fi
done
