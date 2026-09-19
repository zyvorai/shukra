# Attribution

Two kinds of network event exist, and they are never mixed.

**Host events** come from `tcp_v4_connect`, `tcp_v6_connect` and retransmit probes on the host. The socket owner is the VMM process, so they are labeled `attribution: "qemu-process"` and always `guest_attributed: false`. The string is historical: it means the VMM's own socket, including Cloud Hypervisor, Firecracker and `fluxvm-hypervisor`, not only QEMU. That is migration, a remote disk or a management connection. It is not the guest's.

**Guest events** come from the tap program on the host side of a VM's tap interface. They are labeled `attribution: "guest-tap"` and `guest_attributed: true`, and only when the tap belongs to a VM in the current scan. A tap no VM owns is `unattributed`, not a guessed name. There are three kinds:

- `guest_connect`: the guest sent a TCP SYN. `src` is the guest, `dst` and `dport` are where it connected.
- `guest_flow`: the guest started a new UDP flow.
- `guest_inbound`: a TCP SYN was sent **to** the guest, so someone connected in. `src` is the peer, `dst` is the guest and `dport` is the guest port it reached.

The **handshake counters** (what became of each connection: accepted, refused, never answered, blocked) and the **kernel drop counts** (what the host kernel dropped on the tap, and whether it was Shukra) are guest-tap measurements too. They describe the VM's tap, and they are keyed by the tap's owner exactly as the events are, so a tap no VM owns has no row.

Identity for a plain QEMU, libvirt or kubevirt guest comes from the command line: `-name` / `guest=`, `-uuid`, and `ifname=` tap names, and, for libvirt VMs whose taps are passed as file descriptors, the `iff:` line in the process's `fdinfo`. `libvirt` and `kubevirt` are labels derived from that command line. They are not guest agents.

A FluxVM guest is named from FluxVM's VM record (`vms.json`), not from the VMM argv. FluxVM's QEMU command line has neither `-name` nor `-uuid`. The record covers all four backends: QEMU, `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor`. `runtime` is `fluxvm`. Guest traffic is traced on a host interface, never on the tap inside FluxVM's per-VM netns:

- If FluxVM wrote `/run/fluxvm/ebpf/vms/<id>/iface`, that name. `<id>` is the UUID with hyphens removed. This covers a direct, bridge-less tap.
- Otherwise, when the record has `netns` set, the host veth `vh` plus the first 8 hex digits of that id. Ingress on it is traffic from the guest. The guest's address is still the inner one: NAT is POSTROUTING, after this hook.
- Otherwise `tap_name`, the host-bridge or macvtap device.

The full topology, what is skipped (a stopped VM, user-mode NAT), and how that interacts with `fluxvm_egress` is in [FluxVM](tap.md#fluxvm).

`exec` and `exit` events are joined to a VM by the parent's tgid, which the kernel program reads when the event happens, so a short-lived child is still attributed after it has gone. Only children of a watched VMM are emitted at all. The watched set is every QEMU pid and every live FluxVM VMM pid from the last scan.

KVM exit, scheduler, and block counters use the same PID join, against the VMM's thread group. Block latency is that process's I/O thread, not a filesystem inside the guest.

**A detection keeps the attribution of the event that caused it**, so a rule that fires on something the guest did says the guest did it, and a rule that fires on the VMM's own socket says `qemu-process`.

## What is not measured

- **CPU steal**, and which **process** inside the guest made a connection. A guest event names the VM and the address, not the guest process. Shukra never runs anything in the VM.
- **What is inside a connection.** The programs count and sample metadata and never read payloads: HTTP requests and TLS content are not parsed. The one thing read beyond headers is the name in a DNS query over UDP port 53 (see [DNS names](tap.md#dns-names)); DNS over TCP, TLS or HTTPS is seen only as a connection.
- **A VM with no tap it can attach to.** User-mode networking (QEMU SLIRP, including a FluxVM guest with `network.mode` `user`) has no host interface. A tap that is not in the host namespace, and that the scan could not map to one, is the same: no guest events, no drop counts, no isolation. `shukractl doctor` names both (`blind-vms`, or `vm-tap-other-netns` when a name is known but the interface is not here). Host-side counters still work. FluxVM's default per-VM netns is not this case: it is mapped to the host veth and traced. See [FluxVM](tap.md#fluxvm).
- **Traffic that never crosses the tap**, such as two guests on the same host bridge whose traffic does not pass through this tap, vhost-user, and SR-IOV.
