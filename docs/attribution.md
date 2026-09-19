# Attribution

Every network event in this build has `guest_attributed: false`.

A connect or retransmit is labeled `attribution: "qemu-process"` only when its PID or thread-group is the QEMU process or a thread under `/proc/<pid>/task`. Otherwise it is `unattributed` and stays in the host rollup. Shukra does not invent a VM name for it.

Identity comes from the QEMU command line: `-name` / `guest=`, `-uuid`, and `ifname=` tap names. `libvirt` and `kubevirt` are labels derived from that command line. They are not guest agents.

KVM exit, scheduler, and block counters use the same PID join. Block latency is the QEMU I/O thread, not a filesystem inside the guest.

CPU steal, in-guest processes, and traffic on the VM tap are not measured here. See [roadmap-taptrace.md](roadmap-taptrace.md).
