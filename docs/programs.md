# The programs

Back to the [README](../README.md).

Eight programs. Hot paths stay in maps. The ring buffer is only for discrete events, and the events a guest can cause are rate-limited on their own budgets. The host-side ones (`net` connects, and the `sched` and `block` slow-request thresholds) are bounded by the ring, not by a rate.

| Program | Hooks | What it records |
|---|---|---|
| `kvm` | `kvm_exit`, `kvm_entry`, `kvm_mmio`, `kvm_pio` | Exit counts by reason, exit handling time (histogram, halts excluded) and time per reason |
| `sched` | wakeup, switch, exec, exit | On-CPU time, run-queue delay (histogram, per thread), **vCPU preemption** (how long a vCPU was runnable but off a host CPU, and who had it), exec and exit events for QEMU children |
| `block` | `block_rq_insert`, `block_rq_issue`, `block_rq_complete` | Service-time and queue-time histograms, requests, bytes, errors and the slowest request, per direction |
| `net` | `tcp_v4_connect`, `tcp_v6_connect`, sampled `tcp_retransmit_skb` | Exact connect counts (IPv4 and IPv6) and 1-in-64 retransmit samples: **the QEMU process's** sockets |
| `mem` | `mm_vmscan_direct_reclaim_begin`, `mm_vmscan_direct_reclaim_end`, `oom/mark_victim` | Direct reclaim stalls and OOM kills of the VMM process, not the guest's own memory |
| `tap` | TCX ingress and egress on each VM tap (Linux 6.6+) | The guest's own traffic: per-tap counters; an event per TCP connect, per new UDP flow and per connection made *to* the guest; the name in each DNS query over UDP/53; the server name in each TLS ClientHello; what became of each TCP handshake (accepted, refused, never answered, blocked) and how long it took; isolation; and each VM's egress policy |
| `drops` | `skb:kfree_skb` on each VM tap (Linux 5.17+) | What the kernel dropped on the tap and why, by the kernel's own reason and the function that freed it, with Shukra's own isolation drops subtracted, so another program dropping a VM's traffic (Cilium, a dataplane, a `tc` filter) or a guest not reading its NIC is named |
| `vmm` | `openat`, `openat2`, `open`, `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load` syscall tracepoints, plus `sched_process_fork` and `sched_process_exit` to follow descendants | For a QEMU process, and anything it started at any depth: the file it opened and the sensitive call it made, as events. A steady-state VMM does none |

That is 35 attach points in all: 4 + 4 + 3 + 3 + 3 + 2 + 1 + 15. `tap` is attached once per VM interface and comes and goes with the VMs.

Identity comes from the host: the QEMU command line (`-name` / `guest=`, `-uuid`, `ifname=`) and, for libvirt VMs whose taps are passed as file descriptors, the process's `fdinfo`. A FluxVM guest (QEMU, Cloud Hypervisor, Firecracker, or `fluxvm-hypervisor`) is named from FluxVM's `vms.json` instead, and its guest traffic is traced on the host interface, which for the default per-VM netns is the veth `vh<8hex>` rather than the tap inside that namespace. See [FluxVM](tap.md#fluxvm). A PID that is not one of those VMM thread groups rolls up to `_host` as `unattributed`. It is never given a made-up VM name.
