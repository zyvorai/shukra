# Security

Shukra in this build is observe-only.

- eBPF programs count and sample metadata. They do not copy application payload bytes.
- TCP events are host connects from a process, joined to a QEMU thread group when the PID matches. They are not a view of the guest network.
- `shukractl isolate` and `POST /api/v1/isolate` record a userspace decision. `applied` is false. No TC, XDP, or Cilium program is loaded.
- The API expects `Authorization: Bearer` matching `SHUKRA_API_KEY`. The dev default exists only when that variable is unset.
- Report vulnerabilities to the Zyvor maintainers. Do not open a public issue that includes exploit detail.
