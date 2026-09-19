# Guest traffic and isolation (the tap program)

Every other program in Shukra sees the QEMU process. This one sees the guest. It attaches TCX to the host side of each VM's tap interface, so a frame it counts really is the guest's, and events from it are the only ones Shukra marks `guest_attributed: true`.

It does four things: it **counts** the guest's traffic, **records** what the guest connects to and what connects to it, **follows** each TCP handshake to see what became of it, and can **isolate** the VM. A fifth question, *who dropped the packet*, is answered by its sibling program and has its own guide: [where packets die](drops.md). To use the two together to find lost traffic, see the [walkthrough](tutorials/08-lost-traffic.md).

## What it needs

- Linux 6.6 or newer, for TCX. Older kernels report the tap program as detached with `TCX needs Linux 6.6 or newer`. There is no TC fallback yet.
- A VM with a tap interface. The daemon finds a VM's taps two ways and merges them: `ifname=tap0` on the QEMU command line, and the `iff:` line in `/proc/<pid>/fdinfo/<fd>` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its `vnet0` as a file descriptor (`-netdev tap,fd=37`). Reading another user's fds needs the daemon to have `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which the shipped unit grants. If it cannot read them, that VM has no known tap and nothing is attached or isolated for it: a name is never guessed. A VM on user-mode networking has no tap either.

The daemon attaches the program to each VM's tap as the VM appears and takes it off when the VM goes. It shares the hook politely: it returns `TCX_NEXT`, never `TCX_PASS`, so any other program attached to the same tap (Cilium, or another tool) still runs after it. `TCX_PASS` would have accepted the packet and skipped them. `shukractl programs` shows `tap  attached  N taps` once at least one is on.

## What it records

Directions are named from the guest's side. Frames the guest sends are `from_guest` (TCX ingress on the tap), and frames sent to it are `to_guest`.

- **Counters** per tap: packets and bytes each way, and packets and bytes dropped by isolation. Frames the host itself sent and the kernel looped back in (multicast) are not counted as the guest's. `shukractl trace tap`, `GET /api/v1/trace/tap`, and `shukra_tap_*` on `/metrics`.
- **`guest_connect` events**: one per TCP SYN the guest sends (IPv4 and IPv6), with the guest's own source address, the destination and port, the tap, and `proto: "tcp"`. A connect isolation dropped has `blocked: true`.
- **`guest_flow` events**: one per *new* UDP flow (`proto: "udp"`), so a guest's DNS, NTP or a UDP channel out is visible. A flow is announced when its first datagram is seen and again only after 60 seconds, so 20 datagrams on one flow are one event, and a new source port is a new flow. The flow table is a fixed-size LRU, so a guest cannot grow it, only turn it over. Multicast and broadcast (mDNS, SSDP, DHCP discovery) are counted in the tap's packets but produce no event.
- **`guest_inbound` events**: one per TCP connection made **to** the guest, the other way round from `guest_connect`. `src` is the peer that connected, `dst` is the guest, `dport` is the guest port it reached, and `blocked: true` means isolation dropped the SYN. A retransmit of the same SYN is not announced again. This is how you see a service inside a VM being probed, or a watched network reaching in.
- **Handshake outcomes**, per tap and per direction (`shukractl trace tap`, `/api/v1/trace/tap`, `shukra_tap_connect_*`). The tap follows each SYN until it is answered: a SYN-ACK is **accepted**, an RST is **refused**, and a SYN nobody answers is **never answered** (`ignored`, for a connection made to the guest). Isolation's drops are **blocked**. A repeat of the same SYN is a **retransmit**, not a new attempt. So every attempt is exactly one of accepted, refused, never answered or blocked, or is still waiting, and the counts add up. The time from SYN to SYN-ACK of the guest's own connections is a log2 histogram (`handshakeP50Ns`, `handshakeP99Ns`, `shukra_tap_handshake_seconds`).
- Both event kinds are capped at 200 events per tap per second, so a guest that floods SYNs or invents flows cannot flood the event ring. The counters still see every packet.

The detection rules apply to these events as they do to host connects. A `destinations` rule fires on any protocol. A `ports` rule fires on TCP unless it says `proto: udp` or `proto: any`, and on the guest's own connects unless it says `dir: in` (a connection made to the guest, matched on the port it reached) or `dir: any`, so a rule written before either was visible means what it always did. A `destinations` rule also fires when a watched network connects **in**, naming the peer. A detection on guest traffic is itself `guest_attributed: true` with `attribution: "guest-tap"` and carries the `proto`. A host connect and a guest connect to the same address, and TCP and UDP to the same address, are separate alerts, so none of them hides another.

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

Pinning needs a bpf filesystem at `/sys/fs/bpf` (present on any systemd host). Without one the daemon runs unpinned, logs that, and reports `durable: false`; then isolation lasts only while the daemon runs and the isolate response says so. A new map is a new pin, so a build that only adds maps (as the handshake counters did) keeps every existing map and link and isolation is untouched. If a build changes an existing map's layout, the old pins cannot be reused: the daemon replaces them, logs it, and re-applies the recorded isolations, so the cost is a brief gap on upgrade.

### What isolation does not cover

- A SYN is judged "never answered" after 3 seconds, counted when the counters are read, because BPF has no timers. A server that answers after that is counted as never answered and not as accepted. The table of pending SYNs has a fixed size, so under a SYN flood the oldest are forgotten uncounted; `attempts` still counts every one. A daemon restart forgets handshakes that were in flight.
- DHCP: a guest that must renew a lease will fail unless the DHCP server is on the allow list.
- VLAN-tagged frames and IPv6 extension headers are judged by their outer addresses only, and the SYN event needs the TCP header to follow the IPv6 header directly. Traffic that cannot be parsed is dropped while isolated.
- ICMP and other protocols are counted and can be dropped, but do not produce events. UDP events carry addresses and ports, not the DNS name that was asked for.
- Isolation blocks the VM's tap. It does not stop the guest talking to another guest on the same host bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces.
- A VM whose tap lives in another network namespace (a sandbox or container runtime that gives each VM its own) has no tap this daemon can attach to, since it runs in the host's namespace. Such a VM is listed with its tap name but has no tap counters, no guest events and cannot be isolated. `shukractl doctor` names such a VM (`vm-tap-other-netns`, a warning), and you can compare `taps` on `GET /api/v1/vms` with the rows of `GET /api/v1/trace/tap` yourself. A tap that exists here but is not traced yet is a separate, informational finding (`vm-tap-untraced`): it is normal for the moment after a VM starts, and a problem if it stays. Found on a live host where one of ten VMs was like this; fluxvm puts a VM's tap in its own namespace unless its spec says `"netns": false`.

### What the counters count

`to_guest` is what the host offered to the tap, counted before the tap's own driver runs. If the guest is not reading its NIC (a VM stopped at its firmware, or a guest whose NIC driver never came up), the tun driver drops those frames and the kernel's `tx_packets` stays put while `to_guest` keeps rising. Its `tx_dropped` climbs instead. `from_guest` is what the guest sent.

## When guests cannot reach each other

Shukra's program can only drop a frame on a tap that is **isolated**, and it counts every frame it drops (`dropped` in `trace tap`). So if a VM's traffic is being lost and `dropped` is 0, something else is dropping it, and the `drops` program says what: [where packets die](drops.md). The connection counters above say whether the connection got an answer at all. Together they separate a refusing destination, a dropping host and a guest that is not reading its NIC, and the [walkthrough](tutorials/08-lost-traffic.md) shows how.

Three things a real host showed, all about fluxvm and none about Shukra, are in that guide: two guests with the same MAC, a dataplane policy that allows only some CIDRs and ports, and a tap in another network namespace.

## How it was checked

The full account is in [testing](testing.md). For the tap program:

- **`scripts/test-tap.sh`** builds a real network path with no KVM (a namespace for the guest, a veth for the tap, a fake QEMU naming it) and runs on a real kernel in CI. It checks refusal without an allow list; guest events and detections attributed to the VM; the counters; that an allowed address stays reachable and a non-allowed one is dropped over IPv4, IPv6 and ping; that isolation survives a `kill -9`, a restart and a graceful stop and is lifted by `-detach-all`; a real `tun` tap; UDP flows and their rules; drops from a real `tc` filter, told apart from Shukra's own; and **every TCP handshake outcome both ways with exact counts**: on GitHub's kernel, 17 outbound attempts came out as 5 accepted, 6 refused, 4 never answered and 2 blocked with 1 retransmit, and 7 inbound as 3 accepted, 2 refused and 2 ignored, and the identity attempts = accepted + refused + never answered + blocked held.
- **`scripts/test-live-guest.sh`** boots two real KVM guests and checks the same things end to end on a hypervisor: the taps are found and attached as hot-plugs, events are attributed with the guest's own address, packet counts equal the kernel's `rx_packets` and `tx_packets`, the guests reach each other, an accepted and a refused connection are seen from both taps, and deleting the VMs detaches everything.

The rig must never run on a hypervisor already running Shukra: it shares the pin directory and its cleanup detaches every tap.
