# Security

Shukra in this build is observe-only.

- eBPF programs count and sample metadata. They do not copy application payload bytes.
- TCP events are host connects from a process, joined to a QEMU thread group when the PID matches. They are not a view of the guest network.
- `shukractl isolate` and `POST /api/v1/isolate` record a userspace decision. `applied` is false. No TC, XDP, or Cilium program is loaded.
- The API expects `Authorization: Bearer` matching `SHUKRA_API_KEY`. The dev default exists only when that variable is unset, and the daemon says so at start. `SHUKRA_READONLY_KEY` adds a key that can read but not act.
- The API is plain HTTP unless you pass `-tls-cert` and `-tls-key`. The daemon warns when it serves plain HTTP on a non-loopback address.
- The deployed service runs with only `CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_RESOURCE` and a read-only filesystem apart from its data directory. See [Deploy a hypervisor](docs/tutorials/03-deploy.md).
- Report vulnerabilities to the Zyvor maintainers. Do not open a public issue that includes exploit detail.
