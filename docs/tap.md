# Guest traffic and isolation (the tap program)

Every other program in Shukra sees the VMM process: QEMU, or a FluxVM backend. This one sees the guest. It attaches TCX to the host side of each VM's tap, or to the host veth that stands in for that tap, so a frame it counts really is the guest's, and events from it are the only ones Shukra marks `guest_attributed: true`.

It does four things: it **counts** the guest's traffic, **records** what the guest connects to and what connects to it, **follows** each TCP handshake to see what became of it, and can **isolate** the VM. A fifth question, *who dropped the packet*, is answered by its sibling program and has its own guide: [where packets die](drops.md). To use the two together to find lost traffic, see the [walkthrough](tutorials/08-lost-traffic.md).

## What it needs

- Linux 6.6 or newer, for TCX. Older kernels report the tap program as detached with `TCX needs Linux 6.6 or newer`. There is no TC fallback yet.
- A VM with a tap interface. The daemon finds a VM's taps two ways and merges them: `ifname=tap0` on the QEMU command line, and the `iff:` line in `/proc/<pid>/fdinfo/<fd>` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its `vnet0` as a file descriptor (`-netdev tap,fd=37`). Reading another user's fds needs the daemon to have `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which the shipped unit grants. If it cannot read them, that VM has no known tap and nothing is attached or isolated for it: a name is never guessed. A VM on user-mode networking has no tap either.

The daemon attaches the program to each VM's tap as the VM appears and takes it off when the VM goes. It shares the hook politely: it returns `TCX_NEXT`, never `TCX_PASS`, so any other program attached to the same tap (Cilium, FluxVM's `fluxvm_egress`, or another tool) still runs after it. `TCX_PASS` would have accepted the packet and skipped them. `shukractl programs` shows `tap  attached  N taps` once at least one is on.

## FluxVM

[FluxVM](https://github.com/zyvorai/fluxvm) boots a guest with QEMU, Cloud Hypervisor, Firecracker, or its own `fluxvm-hypervisor`. Shukra does not call FluxVM's API and does not load FluxVM's programs. On each scan, after it has walked `/proc` for `qemu-system*`, it reads FluxVM's VM store and joins each live record to the process and to the host interface that actually carries the guest's frames. The BPF programs are unchanged. KVM, scheduler and block counters follow the VMM's threads. Guest connects, UDP flows, DNS names, handshake outcomes, kernel drops and isolation follow that host interface.

### Where the record is

`state_dir` in `/etc/fluxvm.toml`, or `/var/lib/fluxvm` when that line is absent or the file is missing. The store is `{state_dir}/vms.json`: a JSON object whose keys are VM ids and whose values are records. A missing file, an empty file, or a file that does not parse is not an error. The QEMU scan stands, and the daemon keeps serving.

The fields read are `id`, `name`, `pid`, `tap_name` and `netns`. A record with no `pid`, or whose pid is not a live directory in the proc scan, is skipped. That is a stopped or deleted VM, not a guest Shukra failed to see.

`runtime` becomes `fluxvm`. The name and UUID come from the record, not from the VMM command line. FluxVM's QEMU argv does not pass `-name` or `-uuid`, so without the record those guests would show up as `qemu-unnamed` with whatever `ifname=` the inner tap happened to be.

### Which process

A pid the QEMU scan already found is updated in place. It is not listed twice. `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor` are added when that binary is `argv[0]`. Firecracker's `jailer` execs into `firecracker`, so the pid in the record is the Firecracker process, not a leftover jailer. Threads come from `/proc/<pid>/task`. A vCPU thread in that thread group owns the KVM counters the same way a QEMU `CPU n/KVM` thread does.

The process comm stays the binary. The kernel keeps 15 characters of it, so `cloud-hypervisor` is reported as `cloud-hypervis` and `fluxvm-hypervisor` as `fluxvm-hypervis`. `firecracker` and `jailer` fit.

A QEMU, libvirt or kubevirt process that is not in the store is left as the command line described it. `runtime=libvirt` and `runtime=kubevirt` are still labels from that command line, not guest agents.

### Which interface

Guest frames are not the VMM's sockets. They leave the guest on a tap. The daemon runs in the host network namespace and can only attach to an interface that exists there. It picks one, in this order, and does not keep the others:

1. **The edge FluxVM recorded**, when the file `/run/fluxvm/ebpf/vms/<id>/iface` exists and is not empty. `<id>` is the UUID with the hyphens removed. This is the interface FluxVM's own dataplane attached to, including a bridge-less direct tap whose guest device is not in the host namespace.
2. **The host veth of a per-VM netns**, when the record has `netns` set and that file does not. The name is `vh` plus the first 8 hex digits of the same id. FluxVM's default (`"netns": true`) builds this:

```text
host namespace                         VM netns eph-<8hex>
vh<8hex>  <---- veth pair ---->  vn<8hex> -- br<8hex> -- tap<8hex> -- guest
     ^
     TCX ingress = frames the guest sent
     TCX egress  = frames sent to the guest
```

The inner tap is `tap<8hex>`. It is not in the host namespace, so it is not the name Shukra stores and not the interface it attaches to. Directions match a normal tap: ingress is from the guest, egress is toward it. NAT on this path is POSTROUTING on the host, after the TCX hook, so a `guest_connect` still carries the guest's own address (a `169.254` address on the default netns), not the masqueraded one.

3. **`tap_name`**, when there is no netns. That is a host-bridge tap, usually `eph<8hex>`, or a macvtap, already visible in the host namespace.

`shukractl vms` prints that name under `taps=`. For a default netns guest it is `vh…`, not `tap…`. Compare it with `shukractl trace tap`. A name that is not in this namespace is still the doctor finding `vm-tap-other-netns`: Shukra does not enter the namespace. The unit does not have `CAP_SYS_ADMIN`, and the fix is not "set `"netns": false`". A FluxVM guest is supposed to be traced on the host veth. The warning remains for a tap the scan could not map, and for any other runtime whose tap really is elsewhere.

User-mode NAT (`network.mode` `user`, QEMU SLIRP) has no host interface. The VM is listed, `taps` is empty, there are no guest events, no drop counts and no isolation. `shukractl doctor` names it. Host-side KVM, scheduler and block counters still work, because those follow the process, not the tap.

### What each program attributes

| What | Joined by | Notes |
|---|---|---|
| KVM exits, on-CPU time, run-queue delay, block latency | The VMM's thread group | Block latency is the VMM's I/O, not a filesystem inside the guest. A `vhost-*` kernel thread outside the thread group is not included. |
| `exec` and `exit` | The parent's tgid, if that tgid is watched | The watched set is every VMM pid from the scan. `qemu-system*`, `cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor` and `jailer` are allowed execs, so a boot is not an unexpected-exec detection. `cpu`, `io`, `vhost` and `kvm` in the comm are allowed too. |
| Host TCP (`tcp_v4_connect`, `tcp_v6_connect`, retransmits) | The socket owner | `attribution` stays `qemu-process` for every backend. That string means "the VMM's socket, not the guest". It was not renamed, so a client that matches it still matches. |
| Guest connects, flows, inbound SYNs, DNS names, handshakes, drops, isolation | The host interface above | `attribution` is `guest-tap`. DNS names are read from the query on that interface the same way they are on a QEMU tap. |

The live guest test, `scripts/test-live-guest.sh`, still boots two QEMU guests with `"netns": false` on a shared bridge. Those two have to reach each other on one L2 segment, which the default netns does not provide. It does not exercise the host-veth path. That path is covered by the identity tests in `internal/identity`.

## What it records

Directions are named from the guest's side. Frames the guest sends are `from_guest` (TCX ingress on the tap), and frames sent to it are `to_guest`.

- **Counters** per tap: packets and bytes each way, and packets and bytes dropped by isolation. Frames the host itself sent and the kernel looped back in (multicast) are not counted as the guest's. `shukractl trace tap`, `GET /api/v1/trace/tap`, and `shukra_tap_*` on `/metrics`.
- **`guest_connect` events**: one per TCP SYN the guest sends (IPv4 and IPv6), with the guest's own source address, the destination and port, the tap, and `proto: "tcp"`. A connect isolation dropped has `blocked: true`.
- **`guest_flow` events**: one per *new* UDP flow (`proto: "udp"`), so a guest's DNS, NTP or a UDP channel out is visible. A flow is announced when its first datagram is seen and again only after 60 seconds, so 20 datagrams on one flow are one event, and a new source port is a new flow. The flow table is a fixed-size LRU, so a guest cannot grow it, only turn it over. Multicast and broadcast (mDNS, SSDP, DHCP discovery) are counted in the tap's packets but produce no event.
- **`guest_inbound` events**: one per TCP connection made **to** the guest, the other way round from `guest_connect`. `src` is the peer that connected, `dst` is the guest, `dport` is the guest port it reached, and `blocked: true` means isolation dropped the SYN. A retransmit of the same SYN is not announced again. This is how you see a service inside a VM being probed, or a watched network reaching in.
- **Handshake outcomes**, per tap and per direction (`shukractl trace tap`, `/api/v1/trace/tap`, `shukra_tap_connect_*`). The tap follows each SYN until it is answered: a SYN-ACK is **accepted**, an RST is **refused**, and a SYN nobody answers is **never answered** (`ignored`, for a connection made to the guest). Isolation's drops are **blocked**. A repeat of the same SYN is a **retransmit**, not a new attempt. So every attempt is exactly one of accepted, refused, never answered or blocked, or is still waiting, and the counts add up. The time from SYN to SYN-ACK of the guest's own connections is a log2 histogram (`handshakeP50Ns`, `handshakeP99Ns`, `shukra_tap_handshake_seconds`).
- **`guest_dns` events**: the name a guest asked for in a DNS query over UDP port 53. See [DNS names](#dns-names).
- Both event kinds are capped at 200 events per tap per second, so a guest that floods SYNs or invents flows cannot flood the event ring. The counters still see every packet.

The detection rules apply to these events as they do to host connects. A `destinations` rule fires on any protocol. A `ports` rule fires on TCP unless it says `proto: udp` or `proto: any`, and on the guest's own connects unless it says `dir: in` (a connection made to the guest, matched on the port it reached) or `dir: any`, so a rule written before either was visible means what it always did. A `destinations` rule also fires when a watched network connects **in**, naming the peer. A detection on guest traffic is itself `guest_attributed: true` with `attribution: "guest-tap"` and carries the `proto`. A host connect and a guest connect to the same address, and TCP and UDP to the same address, are separate alerts, so none of them hides another.

## DNS names

For a plain DNS query the guest sends to UDP port 53 (IPv4 or IPv6), the tap program checks that it is a query (`QR=0`, `OPCODE=0`, one question) and copies the first 128 bytes of the question section. The daemon decodes the name and the type and emits a `guest_dns` event: `dns_name` (lower-cased, dot-joined), `qtype` (`A`, `AAAA`, `MX`, `TXT`, `HTTPS`, or `TYPE<n>`), the guest as `src` and the resolver as `dst`, with `blocked: true` if isolation dropped the query. The flow to port 53 still produces its own `guest_flow` event: the name adds to the flow and does not replace it.

- **Announced once a minute.** A name and type on a tap is announced when first seen and again after 60 seconds, so a guest that asks for the same name a hundred times is one event. `www.Example.com` and `www.example.com` are the same name. AAAA and A are different queries.
- **Its own budget.** At most 200 names per tap per second, separately from the connect events, so a resolver storm cannot starve them.
- **A name that does not fit** (longer than the copy, about 110 bytes of name) is an event with `dns_truncated: true` and no `qtype`, and the labels that were read. A compression pointer, a response, a second question or something that is not DNS at all produces no event.
- **Sanitised.** Every byte that is not a printable character becomes `?`, and a name is cut at 253 bytes, so a hostile guest cannot put a line break or an escape sequence into a log, a terminal or a consumer.
- **A `dns` rule** (see [detection rules](tutorials/06-watchlist.md)) fires on a name by suffix, exact match or substring. It judges the name only: the resolver's address is not somewhere the guest connected.
- **Privacy.** A name identifies what a VM is doing. It is held in the event list, the flight recorder and, with `-data-dir`, the detection log. `shukrad -dns-events=false` makes the program not look at DNS at all: no name is ever copied out of the kernel. The switch lives in a pinned map and the daemon sets it on every start.

What it does not see: answers (so a name is not tied to the addresses it resolved to), queries over TCP, DNS over TLS or HTTPS, a second question in one packet, and a guest that talks to a resolver on a port other than 53. A packet that is not a query is ignored. Names are decoded in the daemon, not in the kernel, which is why a decoder bug cannot upset the verifier.

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
- ICMP and other protocols are counted and can be dropped, but do not produce events. A UDP event carries addresses and ports; the name in a DNS query is a separate `guest_dns` event.
- Isolation blocks the VM's tap. It does not stop the guest talking to another guest on the same host bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces.
- A VM whose tap is not in the host namespace, and that the scan could not map to one, has nothing to attach to. It is listed with that tap name but has no tap counters, no guest events and cannot be isolated. `shukractl doctor` names it (`vm-tap-other-netns`, a warning). Compare `taps` on `GET /api/v1/vms` with `GET /api/v1/trace/tap`. A tap that exists here but is not traced yet is a separate, informational finding (`vm-tap-untraced`): normal for the moment after a VM starts, and a problem if it stays. FluxVM's default netns is mapped before this check; see [FluxVM](#fluxvm).

### What the counters count

`to_guest` is what the host offered to the tap, counted before the tap's own driver runs. If the guest is not reading its NIC (a VM stopped at its firmware, or a guest whose NIC driver never came up), the tun driver drops those frames and the kernel's `tx_packets` stays put while `to_guest` keeps rising. Its `tx_dropped` climbs instead. `from_guest` is what the guest sent.

## When guests cannot reach each other

Shukra's program can only drop a frame on a tap that is **isolated**, and it counts every frame it drops (`dropped` in `trace tap`). So if a VM's traffic is being lost and `dropped` is 0, something else is dropping it, and the `drops` program says what: [where packets die](drops.md). The connection counters above say whether the connection got an answer at all. Together they separate a refusing destination, a dropping host and a guest that is not reading its NIC, and the [walkthrough](tutorials/08-lost-traffic.md) shows how.

Three things a real host showed, all about FluxVM and none about a bug in the tap program, are in that guide: two guests with the same MAC, a dataplane policy that allows only some CIDRs and ports, and (before host-veth tracing) a guest tap left inside a netns the daemon could not see. The third is now traced; the first two are still FluxVM configuration.

## How it was checked

The full account is in [testing](testing.md). For the tap program:

- **`scripts/test-tap.sh`** builds a real network path with no KVM (a namespace for the guest, a veth for the tap, a fake QEMU naming it) and runs on a real kernel in CI. It checks refusal without an allow list; guest events and detections attributed to the VM; the counters; that an allowed address stays reachable and a non-allowed one is dropped over IPv4, IPv6 and ping; that isolation survives a `kill -9`, a restart and a graceful stop and is lifted by `-detach-all`; a real `tun` tap; UDP flows and their rules; drops from a real `tc` filter, told apart from Shukra's own; and **every TCP handshake outcome both ways with exact counts**: on GitHub's kernel, 17 outbound attempts came out as 5 accepted, 6 refused, 4 never answered and 2 blocked with 1 retransmit, and 7 inbound as 3 accepted, 2 refused and 2 ignored, and the identity attempts = accepted + refused + never answered + blocked held.
- **`scripts/test-live-guest.sh`** boots two real KVM guests through FluxVM, with `"netns": false` on a shared bridge so they can reach each other, and checks the same things end to end: the taps are found and attached as hot-plugs, events are attributed with the guest's own address, packet counts equal the kernel's `rx_packets` and `tx_packets`, the guests reach each other, an accepted and a refused connection are seen from both taps, and deleting the VMs detaches everything. The default per-VM netns is not what this script boots; that mapping is covered by the identity tests. See [FluxVM](#fluxvm).

The rig must never run on a hypervisor already running Shukra: it shares the pin directory and its cleanup detaches every tap.
