# What it does not do

Back to the [README](../README.md).

Read this before you trust it with anything.

- **Host TCP is QEMU's, not the guest's.** `tcp_v4_connect` and `tcp_v6_connect` events are `attribution: "qemu-process"` and `guest_attributed: false`. Only events seen on a VM's tap are `guest_attributed: true`, and only for a tap that belongs to a VM in the current scan. A tap no VM owns stays unattributed. See [attribution](attribution.md).
- **No agent, and no application data, with these exceptions.** Shukra never runs inside a guest and never reads what a guest says to the world. It reads four things beyond headers, and each has a switch:
  - the **name in a plain DNS query** over UDP port 53 (`-dns-events=false` turns it off);
  - the **first segment of a TLS ClientHello**, for its server name, protocols, version and a fingerprint. A ClientHello is sent before anything is encrypted and holds no application data (`-tls-events=false` makes the program read no TCP payload at all);
  - the **names of the files a QEMU process opens**, never their contents, and the first two numeric arguments of the few calls the `vmm` program watches (`-vmm-tripwires=false` does not load it);
  - process names (`comm`) of what a VMM starts and of a process that opens a file.

  Answers, the rest of a TLS connection, and everything else are not read. A name says what a VM is doing and a fingerprint says what software it runs, so they are treated as sensitive: see [Security](../SECURITY.md). Shukra can say *which VM and which address*, not *which process inside the guest*. The guest's own CPU steal counter is not read; the host's view of the same thing, vCPU preemption and who caused it, is measured.
- **Isolation is real, and conditional.** `shukractl isolate` really drops the VM's tap traffic, but only with an explicit management allow list (`-isolate-allow`), and only on Linux 6.6 or newer (TCX). `applied` is `true` only after the kernel took the change. Without an allow list it is refused. On an older kernel the tap program stays detached and the host probes still run. Enforcement survives a daemon crash, restart or stop when `/sys/fs/bpf` is a bpf filesystem.
- **Nothing acts unless you turn it on.** Responses, egress policy and baselines are off until you configure or apply them. A response can only isolate a VM, and by default it only proposes. An egress policy judges what a guest *starts*, not what it answers, and is not a firewall. A baseline says a thing is *new*, never that it is bad.
- **The VMM tripwire is a tripwire, not a sandbox.** It reads a path when the call starts, does not follow symlinks, and does not see a VMM that does none of the things it watches for. See [what it does not see](vmm-tripwires.md#what-it-does-not-see).
- **Advice is for a person.** Idleness is halt time, a lower bound, and only named on Intel hosts. `advise` never resizes anything.
- **A VM Shukra cannot see says so.** User-mode networking has no tap. A tap that is not in the host namespace, and that was not mapped to one, has no guest traffic, no drop counts and cannot be isolated. `shukractl doctor` names it. FluxVM's default per-VM netns is mapped to the host veth and is traced. See [FluxVM](tap.md#fluxvm).
- **A program that is not measuring reports detached, with the reason.** A build without root, clang, or `/sys/kernel/btf/vmlinux` still serves discovered VMs. It never invents a counter, and a VM with no measurement has no series, not a zero.
- **Percentiles can read up to 2x high**, because they come from log2 buckets. See [What each program measures](signals.md) for every caveat.
- **Past verdicts are coarse.** `explain --at` and `incident` read snapshots taken every 5 minutes, say how coarse the answer is, and say so when nothing is stored.
- **Tap: what is not built yet** is listed in [Tap: what is left](roadmap-taptrace.md): VLAN tags and IPv6 extension headers, ICMP events, the guest's own memory, and which process inside the guest. Direct reclaim and OOM kills of the VMM, and block queue time, are measured.

PacketWolf and Zeus OS are the intended consumers of this JSON. They are not in this repository.
