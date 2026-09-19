# Security

Shukra observes by default, and can isolate a VM only when you give it a management allow list.

- eBPF programs count and sample metadata. They do not copy application payload bytes.
- Host TCP events are connects from a process, joined to a QEMU thread group when the PID matches. They are not a view of the guest network. Traffic seen on a VM tap is, and only that is marked `guest_attributed`.
- `shukractl isolate` and `POST /api/v1/isolate` drop a VM's tap traffic through a TCX program, except ARP, IPv6 neighbour discovery and the networks in `-isolate-allow`. Without that list, or without the tap program, the request is refused or only recorded, and `applied` is `false`. It needs the admin key: a read-only key gets 403. Isolation is enforced while `shukrad` runs and is re-applied after a restart, but the tap is open while the daemon is down. See [Guest traffic and isolation](docs/tap.md).
- The API expects `Authorization: Bearer` matching `SHUKRA_API_KEY`. The dev default exists only when that variable is unset, and the daemon says so at start. `SHUKRA_READONLY_KEY` adds a key that can read but not act.
- The API is plain HTTP unless you pass `-tls-cert` and `-tls-key`. The daemon warns when it serves plain HTTP on a non-loopback address.
- The deployed service runs with six capabilities (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`) and a read-only filesystem apart from its data directory. The last two are broad and exist only to read the tap names of VMs run by another user; the daemon does not use ptrace. See [Deploy a hypervisor](docs/tutorials/03-deploy.md).
- Report vulnerabilities to the Zyvor maintainers. Do not open a public issue that includes exploit detail.
