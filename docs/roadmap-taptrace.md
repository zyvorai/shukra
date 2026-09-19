# Tap program: what is left

The tap program, guest attribution and isolate are built. See [Guest traffic and isolation](tap.md). What is not:

- **Pinned links without a bpf filesystem.** Enforcement outlives the daemon only where `/sys/fs/bpf` is a bpf filesystem. Without one it is unpinned and says so.
- **Coexisting with other TCX programs.** The tap program continues the chain, but it attaches at the default position, so a tool that must run before it needs to attach with an explicit anchor. Nothing is ordered yet.
- **Kernels older than 6.6.** TCX is required. A netlink `clsact` fallback would cover 5.x kernels.
- **A DHCP and DNS story for isolated VMs.** Today they are only reachable if they are on the allow list.
- **VLAN tags and IPv6 extension headers** are not parsed past the outer headers.
- **UDP, ICMP and DNS events.** Only TCP SYNs produce events. Everything is counted.
- **Per-VM allow lists.** One allow list applies to every isolated VM.
- **Which process in the guest.** Attribution stops at the VM. CPU steal is not measured either.
