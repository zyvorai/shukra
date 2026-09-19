# Tap program: what is left

The tap program, guest attribution, isolate, handshake outcomes, inbound connections and drop attribution are built. See [Guest traffic and isolation](tap.md) and [where packets die](drops.md). What is not:

- **Pinned links without a bpf filesystem.** Enforcement outlives the daemon only where `/sys/fs/bpf` is a bpf filesystem. Without one it is unpinned and says so.
- **Coexisting with other TCX programs.** The tap program continues the chain, but it attaches at the default position, so a tool that must run before it needs to attach with an explicit anchor. Nothing is ordered yet.
- **Taps in another network namespace.** `shukractl doctor` names such a VM, but the daemon cannot attach to a tap it cannot see. Entering the namespace needs `CAP_SYS_ADMIN`, which the unit does not have, so this is a decision and not just work.
- **Kernels older than 6.6.** TCX is required. A netlink `clsact` fallback would cover 5.x kernels.
- **A DHCP and DNS story for isolated VMs.** Today they are only reachable if they are on the allow list.
- **VLAN tags and IPv6 extension headers** are not parsed past the outer headers.
- **ICMP events.** TCP connects, connections made to the guest and new UDP flows produce events. ICMP is only counted.
- **DNS names.** A DNS flow is seen as a flow to port 53, not as the name that was queried, so what a VM resolves (command and control, exfiltration) is invisible. This is the next tap feature planned: parse the query name of UDP/53 queries into an event, with a rule type to match on it. DoH and DoT would still not be seen.
- **Who took the vCPU's CPU.** CPU steal is not measured. The planned host-side answer is to record, when a vCPU thread is preempted, who preempted it and for how long, per VM. It would be the host's view of preemption, not the guest's steal.
- **Memory pressure.** Direct reclaim stalls and OOM kills of QEMU are not observed, and no program touches memory.
- **Block I/O errors and queue time.** The block program measures latency, not failed requests.
- **Per-VM allow lists.** One allow list applies to every isolated VM.
- **Which process in the guest.** Attribution stops at the VM. CPU steal is not measured either.
