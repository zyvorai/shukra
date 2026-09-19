# Tap program: what is left

The tap program, guest attribution and isolate are built. See [Guest traffic and isolation](tap.md). What is not:

- **Pinned links without a bpf filesystem.** Enforcement outlives the daemon only where `/sys/fs/bpf` is a bpf filesystem. Without one it is unpinned and says so.
- **Coexisting with other TCX programs.** The tap program continues the chain, but it attaches at the default position, so a tool that must run before it needs to attach with an explicit anchor. Nothing is ordered yet.
- **Taps in another network namespace.** `shukractl doctor` names such a VM, but the daemon cannot attach to a tap it cannot see. Entering the namespace needs `CAP_SYS_ADMIN`, which the unit does not have, so this is a decision and not just work.
- **Kernels older than 6.6.** TCX is required. A netlink `clsact` fallback would cover 5.x kernels.
- **A DHCP and DNS story for isolated VMs.** Today they are only reachable if they are on the allow list.
- **VLAN tags and IPv6 extension headers** are not parsed past the outer headers.
- **ICMP events and DNS names.** TCP connects and new UDP flows produce events. ICMP is only counted, and a DNS flow is seen as a flow to port 53, not as the name that was queried.
- **Per-VM allow lists.** One allow list applies to every isolated VM.
- **Which process in the guest.** Attribution stops at the VM. CPU steal is not measured either.
