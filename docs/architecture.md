# Architecture

Shukra is one privileged daemon on the hypervisor, a CLI and a console that only talk to its API, and six eBPF programs. This page is how the pieces fit, for someone who has to operate it, extend it, or decide whether to trust it.

```text
┌───────────────────────── hypervisor ─────────────────────────┐
│  qemu-system   qemu-system   ...    (guests, untouched)      │
│       ▲ tap vnet0   ▲ tap vnet1                              │
│  ┌────┴─────────────┴──────┐   ┌──────────────────────────┐  │
│  │ tap  (TCX, per VM tap)  │   │ kvm sched block net drops│  │
│  │ counters, events,       │   │ tracepoints and kprobes, │  │
│  │ handshakes, isolation   │   │ maps + a small ring      │  │
│  └────┬────────────────────┘   └───────────┬──────────────┘  │
│       │ pinned maps and links               │ maps            │
│  ┌────┴─────────────────────────────────────┴──────────────┐ │
│  │ shukrad: identity, sampler, agent, state, rules, API     │ │
│  └────┬─────────────────────────────────────────────────────┘ │
└───────┼───────────────────────────────────────────────────────┘
        │ bearer key, HTTP or HTTPS :30970
   ┌────┴─────┐   ┌─────────┐   ┌────────────┐   ┌────────────┐
   │ shukractl│   │ console │   │ Prometheus │   │ sinks      │
   └──────────┘   └─────────┘   └────────────┘   └────────────┘
```

## The programs

| Program | Attaches to | Keeps | Notes |
|---|---|---|---|
| `kvm` | `kvm_exit`, `kvm_entry`, `kvm_mmio`, `kvm_pio` | Per-thread exit counts by reason, entry counts, exit-handling time as a log2 histogram and time per reason | Hand-laid tracepoint records, because KVM records are not in vmlinux BTF on 6.8. `kvm_pio` does not exist on arm64 |
| `sched` | `sched_switch`, `sched_wakeup`, `sched_process_exec`, `sched_process_exit` | On-CPU time and run-queue delay per thread, a `watched` set of QEMU thread groups | Exec and exit events are filtered in the kernel to children of QEMU |
| `block` | `block_rq_issue`, `block_rq_complete` | Latency histogram, bytes and requests per direction, slowest request | Attributed to the task that dispatched the request. About 3% land on a kernel worker |
| `net` | `tcp_v4_connect`, `tcp_v6_connect`, `tcp_retransmit_skb` | Exact connect counts; 1 in 64 retransmits become events | QEMU's own sockets. Never the guest |
| `drops` | `skb:kfree_skb` | Per VM tap and drop reason: a count and the kernel function that freed the packet | Filters to VM taps first. Reads the record by field name (CO-RE). See [drops](drops.md) |
| `tap` | TCX ingress and egress on each VM tap (Linux 6.6+) | Counters, TCP handshake outcomes, isolation policy, an event ring | The only program that sees the guest. See [guest traffic](tap.md) |

Each of the first five loads on its own, and a missing hook detaches only that program: a host without a KVM tracepoint still gets scheduler, block and network data. `tap` is attached per VM interface and comes and goes with the VMs, so its status changes at runtime.

**Hot paths stay in maps.** Counters and histograms are BPF maps that userspace reads on a timer. The ring buffer carries discrete events only (an exec, a connect, a slow request), and every producer of events is rate-limited or sampled so a busy guest cannot fill it.

## Identity: joining a number to a VM

Identity comes from the host, never from inside the guest.

- `identity.Scan` walks `/proc` for `qemu-system-*` processes every 2 seconds and reads each command line: `-name` or `guest=`, `-uuid`, `ifname=`. `libvirt` and `kubevirt` are labels derived from that command line, not a guest agent.
- A VM's **threads** come from `/proc/<pid>/task`, each with a role inferred from its name: `vcpu` (`CPU n/KVM`), `iothread`, `vhost`, or `other`.
- A VM's **taps** are found two ways and merged: `ifname=` on the command line, and the `iff:` line in `/proc/<pid>/fdinfo` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its tap as an inherited fd.
- BPF maps are keyed by **thread id**. Userspace folds them into a VM through the thread list. A pid that is not a QEMU thread rolls up to `_host` as `unattributed` and is never given a made-up VM name.
- An event seen on a tap is `guest_attributed` only if the tap belongs to a VM in the current scan.

## The tap program, in detail

It is the only program that touches traffic, so it is the one to understand.

- **TCX, not clsact.** It attaches with TCX (Linux 6.6+), at ingress (frames from the guest) and egress (frames to it), and returns `TCX_NEXT`, never `TCX_PASS`, so anything else on the tap (Cilium, another tool) still runs.
- **Pinned.** Its links and most maps live under `/sys/fs/bpf/shukra/tap/`, which is why isolation outlives the daemon and counters continue across a restart. The pinned maps are `tap_stats`, `tap_policy`, `allow4`, `allow6`, `tap_rate`, `tap_events`, `tap_outcomes`, `tap_handshake_hist` and `tap_timeouts`. `udp_flows` and `pending_syn` (both LRU, both keyed by values the guest controls) are not pinned, so a restart does not inherit stale flows or in-flight handshakes.
- **Upgrades.** Maps are loaded by pin name. A new map is a new pin, so an upgrade that only adds maps keeps every existing map and link. Only a change to an existing map's layout forces the old pins to be replaced, with a brief gap that the daemon closes by re-applying recorded isolations. The rule when changing the program is never to change a pinned map's layout: add a new map.
- **Isolation.** A flag in `tap_policy` per interface index. While set, every frame is dropped except ARP, IPv6 neighbour discovery and addresses in the `allow4`/`allow6` LPM tries.
- **Events.** A 56-byte record in a 256 KiB ring, decoded by offset in `internal/observe/tap.go` (asserted at compile time). One per TCP SYN, per new UDP flow and per SYN sent to the guest, at most 200 per tap per second.
- **Handshakes.** Each SYN is remembered in `pending_syn` until it is answered. A SYN-ACK or RST that matches counts it accepted or refused and forgets it. A SYN never answered is counted by userspace when the counters are read, after 3 seconds, in its own map (BPF has no timers, and a userspace write to a per-CPU value would race the program's increments).

## State, windows and history

`internal/state` is the in-memory truth the API serves. Counters are cumulative since the program attached, which is honest but misleading for "why is it slow **now**", so the state also keeps history:

- A snapshot of every VM's counters is taken at most every **10 seconds** and kept for **6 minutes**. Drop counts and handshake outcomes are snapshotted beside them.
- **Explain, doctor, and the threshold rules read the difference between now and a snapshot one window ago.** The default window is 60 seconds and the longest is 5 minutes. With less than 20 seconds of history the answer falls back to the lifetime and says so. A counter that went backwards was reset, and reads as what happened since the reset, not as a huge number.
- Whether a program is measuring at all is always a lifetime fact, so a quiet minute is never mistaken for a detached program.
- Events (last 2048), detections (last 2048) and the flight recorder (4096 events per VM) are bounded rings.

## Detection

Rules live in one YAML file (`-watchlist`), re-read on `SIGHUP`:

- **destinations**: a CIDR watchlist, matched on the address a connect went to, or the peer that connected in.
- **ports**: a port, with `proto` (`tcp`, `udp`, `any`) and `dir` (`out`, `in`, `any`).
- **exec_allow**: names that may start under QEMU without an alert.
- **thresholds**: a per-VM metric over a window (block p99, run-queue delay, retransmits, KVM exit rate and latency, guest drops, connection failures, inbound connections).
- **suppress**: a repeat of the same detection inside a window is held back and counted.

A detection keeps the attribution of the event that caused it, so a rule that fires on something the guest did says the guest did it. Detections go to the API, the console and any configured sink (signed webhook, syslog, JSONL file), each with its own queue so a stuck webhook cannot delay the others.

## Persistence

By default everything is in memory. With `-data-dir`, detections and isolation records are appended to JSONL logs (rolling at 16 MiB), and the recorder is saved every minute and on a clean shutdown. Counters and the event list are not saved: they are read back from the kernel or rebuilt.

## Privilege and trust

The unit runs as root with six capabilities and a read-only filesystem apart from its data directory:

| Capability | Why |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, raise the map limit |
| `CAP_NET_ADMIN` | load and attach the TCX tap program |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun fds of a QEMU that runs as another user |

Nothing here reads packet payloads: the programs count and sample metadata, and the DNS and application layers are not parsed. See [SECURITY.md](../SECURITY.md).

## Kernel requirements

| Feature | Needs |
|---|---|
| Any program | BTF at `/sys/kernel/btf/vmlinux`, and `CAP_BPF` (Linux 5.8+) |
| `drops` | Linux 5.17+ (a drop reason on `kfree_skb`) |
| `tap` (guest traffic, handshakes, isolation) | Linux 6.6+ (TCX). Older kernels report it detached, and the rest works |
| Reading libvirt VMs' taps | `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` |

A build without root, clang or BTF still serves discovered VMs and reports every program `detached` with the reason. It never invents a counter.

## Where things are

| Path | What |
|---|---|
| `bpf/*.bpf.c`, `bpf/event.h` | The programs and the shared event layout |
| `internal/bpfgen` | Loads and attaches them (CO-RE via bpf2go). `tap.go` is the tap manager |
| `internal/observe` | Reads the maps, decodes events, joins the loaders to the rest. Has a stub for builds without BPF |
| `internal/identity` | Finds QEMU, its threads and its taps |
| `internal/aggregate` | Turns per-thread maps into per-VM rows, deltas and clones |
| `internal/state` | The in-memory truth, history, Explain, doctor |
| `internal/detect`, `internal/agent` | Rules, thresholds, suppression, and the loop that applies them |
| `internal/api`, `internal/sink`, `internal/persist` | The HTTP API and metrics, alert sinks, on-disk logs |
| `cmd/shukrad`, `cmd/shukractl` | The daemon and the CLI |
| `web/` | The console |
