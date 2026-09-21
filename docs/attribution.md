# Attribution

Every event names a VM or says it cannot, and it says which place it was seen. They are never mixed: the label an event carries is the one that tells you what it can be used to claim.

| Seen | Programs | `attribution` | `guest_attributed` | Means |
|---|---|---|---|---|
| On the host, at the VMM process | `net`, `sched`, `block`, `kvm` | `qemu-process`, or `unattributed` | `false` | What the VMM process did |
| On the host, at the VMM process tree | `vmm` | `qemu-process` | `false` | What the VMM, or something it started, opened or called |
| On the host side of a VM's tap | `tap`, `drops` | `guest-tap` | `true` | What the guest sent or was sent |
| On the host, at the routing socket | none (Netlink in the daemon) | `host-netlink` | `false` | A link, address, route or neighbor changed. No VM |

`guest_attributed` is `true` only for an event seen on a VM's tap **and** naming a VM in the current scan. It is derived in one place (`event.Normalize`) from the attribution and a VM name, and derived again for everything read back from disk, so a stored `guest_attributed: true` is never trusted on its own. A tap no VM owns is `unattributed`, not a guessed name.

## Host events

`tcp_v4_connect`, `tcp_v6_connect` and retransmit probes come from the host kernel. The socket owner is the VMM process, so they are labeled `attribution: "qemu-process"` and always `guest_attributed: false`. The string is historical: it means the VMM's own socket, including Cloud Hypervisor, Firecracker and `fluxvm-hypervisor`, not only QEMU. That is migration, a remote disk or a management connection. It is not the guest's. The probes fire for every process on the host, so a connect by a process no VM owns is stored too, as `unattributed` under `_host`.

`exec` and `exit` events are joined to a VM by the parent's tgid, which the kernel program reads when the event happens, so a short-lived child is still attributed after it has gone. Only a watched VMM and its direct children are emitted at all. The watched set is every QEMU pid and every live FluxVM VMM pid from the last scan.

KVM exit, scheduler (including vCPU preemption, and who took the CPU), and block counters use the same PID join, against the VMM's thread group. A preemptor that is another QEMU thread is named by its VM; anything else is a host command name. Block latency is that process's I/O thread, not a filesystem inside the guest.

## VMM tripwire events

`vmm_file_open` and `vmm_syscall` come from the `vmm` program, which reports what a VMM process, or something a VMM started, opened or called. They are `qemu-process` and `guest_attributed: false`: they are what the VMM did, not the guest. The kernel names the VMM each process descends from, so a shell the VMM started, and the program the shell ran, belong to that VM although they are not among its threads. A VMM the scan no longer knows leaves the event `unattributed`, with no detection made from it. See [VMM tripwires](vmm-tripwires.md).

## Host control-plane events

`netlink_link`, `netlink_address`, `netlink_route`, `netlink_neighbor` and `netlink_error` come from the daemon's routing Netlink socket, not from a program and not from a process. They are `attribution: "host-netlink"` and `guest_attributed: false`, and they name no VM. A deleted route is a fact about the host. It is not evidence that a guest or QEMU deleted it. See [Netlink control-plane events](netlink.md).

## Guest events

Guest events come from the tap program on the host side of a VM's tap interface. They are labeled `attribution: "guest-tap"` and `guest_attributed: true`, and only when the tap belongs to a VM in the current scan. There are five kinds:

- `guest_connect`: the guest sent a TCP SYN. `src` is the guest, `dst` and `dport` are where it connected.
- `guest_flow`: the guest started a new UDP flow.
- `guest_inbound`: a TCP SYN was sent **to** the guest, so someone connected in. `src` is the peer, `dst` is the guest and `dport` is the guest port it reached.
- `guest_dns`: the name in a plain DNS query the guest sent to UDP port 53. `src` is the guest, `dst` the resolver.
- `guest_tls`: the server name, protocols, version and fingerprint in a TLS ClientHello the guest sent.

A connect or flow that the VM's [egress policy](egress-policy.md) judged to be outside its list also carries `policy` (`audit` or `enforce`), set by the tap program and not by anything in the packet.

The **handshake counters** (what became of each connection: accepted, refused, never answered, blocked) and the **kernel drop counts** (what the host kernel dropped on the tap, and whether it was Shukra) are guest-tap measurements too. They describe the VM's tap, and they are keyed by the tap's owner exactly as the events are, so a tap no VM owns has no row.

## Identity

Identity comes from the host, never from inside the guest. For a plain QEMU, libvirt or kubevirt guest it comes from the command line: `-name` / `guest=`, `-uuid`, and `ifname=` tap names, and, for libvirt VMs whose taps are passed as file descriptors, the `iff:` line in the process's `fdinfo`. `libvirt` and `kubevirt` are labels derived from that command line. They are not guest agents.

A FluxVM guest is named from FluxVM's VM record (`vms.json`), not from the VMM argv. FluxVM's QEMU command line has neither `-name` nor `-uuid`. The record covers all four backends: QEMU, `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor`. `runtime` is `fluxvm`. Guest traffic is traced on a host interface, never on the tap inside FluxVM's per-VM netns:

- If FluxVM wrote `/run/fluxvm/ebpf/vms/<id>/iface`, that name. `<id>` is the UUID with hyphens removed. This covers a direct, bridge-less tap.
- Otherwise, when the record has `netns` set, the host veth `vh` plus the first 8 hex digits of that id. Ingress on it is traffic from the guest. The guest's address is still the inner one: NAT is POSTROUTING, after this hook.
- Otherwise `tap_name`, the host-bridge or macvtap device.

The full topology, what is skipped (a stopped VM, user-mode NAT), and how that interacts with `fluxvm_egress` is in [FluxVM](tap.md#fluxvm).

A VM is its **name** everywhere it is remembered. Learned baselines and egress policies are keyed by the name the scan reports, so a VM that is renamed starts a new baseline and policy, and two VMs that are given the same name would share one.

## Detections

**A detection keeps the attribution of the event that caused it**, so a rule that fires on something the guest did says the guest did it, a rule that fires on the VMM's own socket says `qemu-process`, and a tripwire detection says the VMM did it. A baseline's `new-*` detection and an egress policy's `egress-policy-*` detection come from guest events and are guest-attributed.

Detections that describe Shukra's own state carry no event to inherit from: the threshold rules, the response engine's `action-*` announcements and the policy engine's `policy-*` announcements. They name the VM and are `qemu-process`, not guest-attributed. A rule fires on a host-side number, or on a decision a person or the daemon made about the VM. It is not something the guest did.

## What is not measured

- **The guest's own CPU steal counter**, and which **process** inside the guest made a connection. A guest event names the VM and the address, not the guest process. Shukra never runs anything in the VM.
- **What is inside a connection.** The programs count and sample metadata and never read application data: HTTP requests and TLS content are not parsed. What is read beyond headers is the name in a DNS query over UDP port 53 (see [DNS names](tap.md#dns-names)), the server name and offered parameters of a TLS ClientHello (see [TLS server names](tap.md#tls-server-names)), and the names of files a VMM process opens (never their contents). DNS over TCP, TLS or HTTPS is seen only as a connection, or by the hello's server name when there is one. A name hidden by Encrypted Client Hello is only the outer name, and QUIC is not read.
- **A VM with no tap it can attach to.** User-mode networking (QEMU SLIRP, including a FluxVM guest with `network.mode` `user`) has no host interface. A tap that is not in the host namespace, and that the scan could not map to one, is the same: no guest events, no drop counts, no isolation. `shukractl doctor` names both (`blind-vms`, or `vm-tap-other-netns` when a name is known but the interface is not here). Host-side counters still work. FluxVM's default per-VM netns is not this case: it is mapped to the host veth and traced. See [FluxVM](tap.md#fluxvm).
- **Traffic that never crosses the tap**, such as two guests on the same host bridge whose traffic does not pass through this tap, vhost-user, and SR-IOV.
- **A VMM that has been taken over can change what the host reads about it.** Identity is the host's view of the VMM process, including its command line. The `vmm` program is a tripwire for that case and not a defence against it.
