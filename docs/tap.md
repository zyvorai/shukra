# Guest traffic and isolation (the tap program)

Every other program in Shukra sees the QEMU process. This one sees the guest. It attaches TCX to the host side of each VM's tap interface, so a frame it counts really is the guest's, and events from it are the only ones Shukra marks `guest_attributed: true`.

## What it needs

- Linux 6.6 or newer, for TCX. Older kernels report the tap program as detached with `TCX needs Linux 6.6 or newer`. There is no TC fallback yet.
- A VM with a tap interface. The daemon finds a VM's taps two ways and merges them: `ifname=tap0` on the QEMU command line, and the `iff:` line in `/proc/<pid>/fdinfo/<fd>` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its `vnet0` as a file descriptor (`-netdev tap,fd=37`). Reading another user's fds needs the daemon to have `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which the shipped unit grants. If it cannot read them, that VM has no known tap and nothing is attached or isolated for it: a name is never guessed. A VM on user-mode networking has no tap either.

The daemon attaches the program to each VM's tap as the VM appears and takes it off when the VM goes. It shares the hook politely: it returns `TCX_NEXT`, never `TCX_PASS`, so any other program attached to the same tap (Cilium, or another tool) still runs after it. `TCX_PASS` would have accepted the packet and skipped them. `shukractl programs` shows `tap  attached  N taps` once at least one is on.

## What it records

Directions are named from the guest's side. Frames the guest sends are `from_guest` (TCX ingress on the tap), and frames sent to it are `to_guest`.

- **Counters** per tap: packets and bytes each way, and packets and bytes dropped by isolation. Frames the host itself sent and the kernel looped back in (multicast) are not counted as the guest's. `shukractl trace tap`, `GET /api/v1/trace/tap`, and `shukra_tap_*` on `/metrics`.
- **`guest_connect` events**: one per TCP SYN the guest sends (IPv4 and IPv6), with the guest's own source address, the destination and port, the tap, and `proto: "tcp"`. A connect isolation dropped has `blocked: true`.
- **`guest_flow` events**: one per *new* UDP flow (`proto: "udp"`), so a guest's DNS, NTP or a UDP channel out is visible. A flow is announced when its first datagram is seen and again only after 60 seconds, so 20 datagrams on one flow are one event, and a new source port is a new flow. The flow table is a fixed-size LRU, so a guest cannot grow it, only turn it over. Multicast and broadcast (mDNS, SSDP, DHCP discovery) are counted in the tap's packets but produce no event.
- Both kinds are capped at 200 events per tap per second, so a guest that floods SYNs or invents flows cannot flood the event ring. The counters still see every packet.

The detection rules apply to these events as they do to host connects. A `destinations` rule fires on any protocol. A `ports` rule fires on TCP unless it says `proto: udp` or `proto: any`, so a rule written before UDP was visible means what it always did. A detection on guest traffic is itself `guest_attributed: true` with `attribution: "guest-tap"` and carries the `proto`. A host connect and a guest connect to the same address, and TCP and UDP to the same address, are separate alerts, so none of them hides another.

## What guest_attributed means now

`guest_attributed` is `true` only when the event was seen on a VM's tap **and** the tap belongs to a VM in the current scan. A tap no VM owns produces an unattributed event, never a guessed name. Host `tcp_v4_connect` events are still `attribution: "qemu-process"` and `guest_attributed: false`: that is QEMU's own socket, not the guest.

Still not measured: CPU steal, and what runs inside the guest. A guest connect tells you which VM and which address, not which process.

## Isolate

`shukractl isolate <vm>` sets a flag on the VM's tap. While it is set, the program drops every frame on that tap except:

- ARP, and IPv6 neighbour discovery (ICMPv6 types 133 to 137), so the guest can still find an allowed address
- traffic to or from the **management allow list**

The allow list is required. Start the daemon with the networks an isolated VM must keep reaching, usually your management and monitoring networks and the default gateway they sit behind:

```bash
shukrad -isolate-allow 10.0.0.0/24,fd00:10::/64 ...
# or in /etc/shukra/env:  SHUKRA_EXTRA_ARGS=-isolate-allow 10.0.0.0/24
```

**Without an allow list, isolate is refused** (`applied: false`, result `refused`), because an isolated VM that could reach nothing could not be reached by the host that isolated it. A request is also refused for an unknown VM, a VM with no tap, or a daemon without the tap program.

`applied` is `true` only after the kernel program took the change on every tap of the VM. If some taps changed and some did not, the result is `partial`, `applied` is `false`, and what took effect is kept: a half-isolated VM is safer left contained than silently reopened.

`shukractl release <vm>` lifts it. The console's Isolate page enables the controls only when the daemon reports enforcement is available, and asks for a second confirmation that names what will be cut off and what stays reachable.

### Isolation outlives the daemon

The tap program's links and maps are pinned under `/sys/fs/bpf/shukra/tap/`, so the kernel keeps enforcing when `shukrad` is not running:

- **A crash or `kill -9`** leaves every tap exactly as it was. An isolated VM stays isolated, and its allowed management addresses keep working, because the program and its maps are still there.
- **A restart** adopts what is pinned: it points the existing links at the freshly loaded program (`BPF_LINK_UPDATE`, so there is no gap and no second pair of links), and reads the isolation flag back from the kernel, so what it reports is what the kernel is enforcing. Counters continue across the restart.
- **A graceful stop** (`systemctl stop`) detaches every tap that is **not** isolated, so nothing of Shukra is left on a VM's interface once it is off. An isolated tap is left enforcing, on purpose: stopping the daemon must not reopen a VM that was cut off.
- **A VM that went away while the daemon was down** has its stale link removed on the next start, and an interface that was replaced under the same name is re-attached fresh.

The recorded isolations still matter. When the kernel state is gone but the record says "isolated", as after a reboot, the daemon re-applies it on start. A release is recorded too, so a released VM is not re-isolated.

To lift enforcement without the daemon, for an emergency or an uninstall:

```bash
shukrad -detach-all -data-dir /var/lib/shukra
```

It removes every pinned link and map, so every VM is open again, and with `-data-dir` it also records a release for each isolated VM, so the next start does not isolate them again. Without `-data-dir` it says that a restart will re-apply them. The `.deb` runs this on removal, since removing the package removes the thing that could release an isolation.

Pinning needs a bpf filesystem at `/sys/fs/bpf` (present on any systemd host). Without one the daemon runs unpinned, logs that, and reports `durable: false`; then isolation lasts only while the daemon runs and the isolate response says so. If a new build changes the map layout, the old pins cannot be reused: the daemon replaces them, logs it, and re-applies the recorded isolations, so the cost is a brief gap on upgrade.

### What isolation does not cover

- DHCP: a guest that must renew a lease will fail unless the DHCP server is on the allow list.
- VLAN-tagged frames and IPv6 extension headers are judged by their outer addresses only, and the SYN event needs the TCP header to follow the IPv6 header directly. Traffic that cannot be parsed is dropped while isolated.
- ICMP and other protocols are counted and can be dropped, but do not produce events. UDP events carry addresses and ports, not the DNS name that was asked for.
- Isolation blocks the VM's tap. It does not stop the guest talking to another guest on the same host bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces.

## How it was checked

`scripts/test-tap.sh` builds a real network path with no KVM: a network namespace stands in for the guest, a veth pair's host end stands in for the tap, and a fake QEMU process names that interface. It checks refusal without an allow list; guest events and detections attributed to the VM; the tap counters; that an allowed address stays reachable and a non-allowed one is dropped, over IPv4, IPv6 and ping, with the same address reachable again after release; the blocked-connect event; re-application after a daemon restart; no re-isolation of a released VM; and detaching when the VM goes. It also proves enforcement outlives the daemon: a `kill -9` leaves the VM cut off, a restart adopts the links without adding a second pair, a graceful stop detaches a non-isolated tap and leaves an isolated one, and `-detach-all` reopens the VM and records the release. It runs on Linux 6.6 or newer as root and is part of CI.
