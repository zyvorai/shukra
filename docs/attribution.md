# Attribution

Two kinds of network event exist, and they are never mixed.

**Host events** come from `tcp_v4_connect`, `tcp_v6_connect` and retransmit probes on the host. The socket owner is the QEMU process, so they are labeled `attribution: "qemu-process"` and always `guest_attributed: false`. That is QEMU's own traffic, such as migration or a remote disk, not the guest's. A connect or retransmit is labeled `qemu-process` only when its PID or thread-group is the QEMU process or a thread under `/proc/<pid>/task`. Otherwise it is `unattributed` and stays in the host rollup. Shukra does not invent a VM name for it.

**Guest events** come from the tap program on the host side of a VM's tap interface. They are labeled `attribution: "guest-tap"` and `guest_attributed: true`, and only when the tap belongs to a VM in the current scan. A tap no VM owns is `unattributed`, not a guess. See [Guest traffic and isolation](tap.md).

Identity comes from the QEMU command line: `-name` / `guest=`, `-uuid`, and `ifname=` tap names. `libvirt` and `kubevirt` are labels derived from that command line. They are not guest agents.

`exec` and `exit` events are joined to a VM by the parent's tgid, which the kernel program reads when the event happens, so a short-lived child is still attributed after it has gone. Only children of a QEMU process are emitted at all.

KVM exit, scheduler, and block counters use the same PID join. Block latency is the QEMU I/O thread, not a filesystem inside the guest.

Not measured: CPU steal, and which process inside the guest made a connection. A guest event names the VM and the address, not the guest process.
