# Attribution

Two kinds of network event exist, and they are never mixed.

**Host events** come from `tcp_v4_connect`, `tcp_v6_connect` and retransmit probes on the host. The socket owner is the QEMU process, so they are labeled `attribution: "qemu-process"` and always `guest_attributed: false`. That is QEMU's own traffic, such as migration, a remote disk or a management connection. It is not the guest's.

**Guest events** come from the tap program on the host side of a VM's tap interface. They are labeled `attribution: "guest-tap"` and `guest_attributed: true`, and only when the tap belongs to a VM in the current scan. A tap no VM owns is `unattributed`, not a guessed name. There are three kinds:

- `guest_connect`: the guest sent a TCP SYN. `src` is the guest, `dst` and `dport` are where it connected.
- `guest_flow`: the guest started a new UDP flow.
- `guest_inbound`: a TCP SYN was sent **to** the guest, so someone connected in. `src` is the peer, `dst` is the guest and `dport` is the guest port it reached.

The **handshake counters** (what became of each connection: accepted, refused, never answered, blocked) and the **kernel drop counts** (what the host kernel dropped on the tap, and whether it was Shukra) are guest-tap measurements too. They describe the VM's tap, and they are keyed by the tap's owner exactly as the events are, so a tap no VM owns has no row.

Identity comes from the QEMU command line: `-name` / `guest=`, `-uuid`, and `ifname=` tap names, and, for libvirt VMs whose taps are passed as file descriptors, the `iff:` line in the process's `fdinfo`. `libvirt` and `kubevirt` are labels derived from that command line. They are not guest agents.

`exec` and `exit` events are joined to a VM by the parent's tgid, which the kernel program reads when the event happens, so a short-lived child is still attributed after it has gone. Only children of a QEMU process are emitted at all.

KVM exit, scheduler, and block counters use the same PID join. Block latency is the QEMU I/O thread, not a filesystem inside the guest.

**A detection keeps the attribution of the event that caused it**, so a rule that fires on something the guest did says the guest did it, and a rule that fires on QEMU's own socket says it was QEMU's.

## What is not measured

- **CPU steal**, and which **process** inside the guest made a connection. A guest event names the VM and the address, not the guest process. Shukra never runs anything in the VM.
- **What is inside a connection.** The programs count and sample metadata and never read payloads: a guest's DNS names, HTTP requests and TLS content are not parsed. A DNS flow is seen as a flow to port 53.
- **A VM with no tap it can attach to.** A VM on user-mode networking has no tap, and a VM whose tap is in another network namespace (fluxvm's default) is one Shukra cannot see from the host's namespace. `shukractl doctor` names both. Their host-side counters still work; their guest traffic is not visible and they cannot be isolated.
- **Traffic that never crosses the tap**, such as two guests on the same host bridge whose traffic does not pass through this tap, vhost-user, and SR-IOV.
