# Architecture

Back to the [README](../README.md).

```text
┌──────────────────── hypervisor ────────────────────┐
│  VMM processes                 (guests untouched)  │
│      ▲ tap or host veth vh*                        │
│  kvm / sched / block / net / drops / vmm / tap     │  eBPF, CO-RE, maps + small rings
│              │                                     │
│           shukrad                                  │  identity, sampler, rules, responses, state, API
│         :30970 API                                 │
└──────────────┬─────────────────────────────────────┘
               │ bearer
       ┌───────┴────────┐
   shukractl         console
```

Events that leave the daemon carry `product: "shukra"`. A joined host event has `attribution: "qemu-process"` (this includes what a VMM or something it started opened or called), an event seen on a VM's tap has `attribution: "guest-tap"`, a host link, address, route or neighbor change has `attribution: "host-netlink"`, and an unowned PID has `attribution: "unattributed"`. How identity, the tap program, history windows and detection fit together is in [architecture](architecture.md).
