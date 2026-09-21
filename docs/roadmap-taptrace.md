# Tap program: what is left

The tap program is built: guest attribution, isolate, handshake outcomes, inbound connections, DNS names, TLS server names, the per-VM egress policy, and drop attribution. See [Guest traffic and isolation](tap.md), [where packets die](drops.md) and [egress policy](egress-policy.md). What is not:

## The hook

- **Pinned links without a bpf filesystem.** Enforcement outlives the daemon only where `/sys/fs/bpf` is a bpf filesystem. Without one it is unpinned and says so (`durable: false`).
- **Coexisting with other TCX programs.** The tap program continues the chain, but it attaches at the default position, so a tool that must run before it needs to attach with an explicit anchor. Nothing is ordered yet.
- **Taps in a namespace Shukra cannot map.** FluxVM's default per-VM netns is traced on the host veth; see [FluxVM](tap.md#fluxvm). What remains is a tap that is not in the host namespace and that no record maps to a host interface. Entering that namespace needs `CAP_SYS_ADMIN`, which the unit does not have, so this is a decision and not just work. `shukractl doctor` names the VM (`vm-tap-other-netns`).
- **VLAN tags and IPv6 extension headers** are not parsed past the outer headers.

## What it sees

- **ICMP events.** TCP connects, connections made to the guest and new UDP flows produce events. ICMP is only counted.
- **DNS beyond the query name.** Names of queries over UDP port 53 are recorded (`guest_dns`). Answers are not read, so a name is not mapped to the addresses it resolved to. Queries over TCP port 53 and DNS over TLS or HTTPS are not read, nor are second questions or compressed names.
- **TLS beyond the first hello.** A guest that reaches a resolver over TLS is still seen going there by the server name in its hello (`guest_tls`), unless Encrypted Client Hello hides it. QUIC and HTTP/3 (UDP) are not read, a hello that does not start at the beginning of a segment is not seen, and a hello split over segments is read as far as the first one goes (no fingerprint). The server's answer is not read, so whether a connection succeeded or which certificate it got is not known.
- **Which process in the guest.** Attribution stops at the VM.
- **Steal as the guest counts it.** The host's view is measured (vCPU preemption, and who caused it). The guest's own steal counter is not read: it would need something inside the guest.

## What it can do

- **Per-VM management allow lists.** Isolation still uses one allow list for every isolated VM (`-isolate-allow`). Each VM can have its own list under an egress policy, but that is a different thing: it says where a VM may start connections, and the management list stays the floor under it.
- **Egress by port or by name.** An egress policy judges the network a connection goes to (IPv4 /24 and IPv6 /64 when learned from a baseline, anything you give when written by hand). It has no ports and no names, so a policy by server name is not built, and a proposal is as coarse as the baseline it learned from.
- **A DHCP and DNS story for isolated VMs.** Today they are only reachable if they are on the allow list, and under an egress policy a resolver or a DHCP server has to be on the VM's list.

## Beyond the tap

- **Memory pressure.** Direct reclaim stalls and OOM kills of QEMU are not observed, and no program touches memory.
- **Block I/O errors and queue time.** The block program measures latency, not failed requests.
