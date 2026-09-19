# Tap program: what is left

The tap program, guest attribution and isolate are built. See [Guest traffic and isolation](tap.md). What is not:

- **Pinned links.** Isolation is held by the running daemon, so the tap is open while `shukrad` is down. Pinning the TCX links and their maps under `/sys/fs/bpf/shukra` would let enforcement outlive a restart or crash.
- **Kernels older than 6.6.** TCX is required. A netlink `clsact` fallback would cover 5.x kernels.
- **A DHCP and DNS story for isolated VMs.** Today they are only reachable if they are on the allow list.
- **VLAN tags and IPv6 extension headers** are not parsed past the outer headers.
- **UDP, ICMP and DNS events.** Only TCP SYNs produce events. Everything is counted.
- **Per-VM allow lists.** One allow list applies to every isolated VM.
- **Which process in the guest.** Attribution stops at the VM. CPU steal is not measured either.
