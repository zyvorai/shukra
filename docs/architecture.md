# Architecture

Shukra is one privileged daemon on the hypervisor, a CLI and a console that only talk to its API, and six eBPF programs. This page is how the pieces fit, for someone who has to operate it, extend it, or decide whether to trust it.

```text
┌───────────────────────── hypervisor ─────────────────────────┐
│  VMM (qemu, cloud-hypervisor, firecracker, fluxvm-hypervisor)│
│      ▲ tap or host veth vh*   (guests untouched)             │
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
| `sched` | `sched_switch`, `sched_wakeup`, `sched_process_exec`, `sched_process_exit` | On-CPU time, run-queue delay and vCPU preemption (runnable but off CPU, and who took it) per thread, a `watched` set of VMM thread groups | Exec and exit events are filtered in the kernel to children of a watched VMM (QEMU, or a FluxVM backend) |
| `block` | `block_rq_issue`, `block_rq_complete` | Latency histogram, bytes and requests per direction, slowest request | Attributed to the task that dispatched the request. About 3% land on a kernel worker |
| `net` | `tcp_v4_connect`, `tcp_v6_connect`, `tcp_retransmit_skb` | Exact connect counts; 1 in 64 retransmits become events | The VMM's own sockets. Never the guest. The attribution string is still `qemu-process` |
| `drops` | `skb:kfree_skb` | Per VM tap and drop reason: a count and the kernel function that freed the packet | Filters to VM taps first. Reads the record by field name (CO-RE). See [drops](drops.md) |
| `tap` | TCX ingress and egress on each VM's host interface (Linux 6.6+) | Counters, TCP handshake outcomes, isolation policy, an event ring | The only program that sees the guest. On FluxVM's default netns the interface is the host veth, not the inner tap. See [guest traffic](tap.md) |

The `sched` program's preemption tables (`preempt_start`, `preempt_by`) are small LRUs that only QEMU threads ever enter; the per-thread totals in `sched_stats` are the exact ones. See [vCPU preemption](signals.md#vcpu-preemption).

Each of the first five loads on its own, and a missing hook detaches only that program: a host without a KVM tracepoint still gets scheduler, block and network data. `tap` is attached per VM interface and comes and goes with the VMs, so its status changes at runtime.

**Hot paths stay in maps.** Counters and histograms are BPF maps that userspace reads on a timer. The ring buffer carries discrete events only (an exec, a connect, a slow request), and every producer of events is rate-limited or sampled so a busy guest cannot fill it.

## Identity: joining a number to a VM

Identity comes from the host, never from inside the guest.

- `identity.Scan` walks `/proc` every 2 seconds. A `qemu-system*` process is read from its command line: `-name` or `guest=`, `-uuid`, `ifname=`. `libvirt` and `kubevirt` are labels derived from that command line, not a guest agent.
- When FluxVM is installed, the same scan reads `{state_dir}/vms.json` (`state_dir` from `/etc/fluxvm.toml`, otherwise `/var/lib/fluxvm`). Each record with a live pid is a VM: QEMU pids already found are updated, and `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor` are added. `runtime` is `fluxvm`. The name and UUID come from the record, because FluxVM's QEMU argv has neither `-name` nor `-uuid`. A missing store is ignored.
- The interface traced is, in order, `/run/fluxvm/ebpf/vms/<id>/iface` if FluxVM wrote one, else the host veth `vh` plus the first 8 hex digits of the id when `netns` is set, else `tap_name`. The inner `tap<8hex>` of a per-VM netns is not kept. Detail, including why ingress on that veth is "from the guest", is in [FluxVM](tap.md#fluxvm).
- A VM's **threads** come from `/proc/<pid>/task`, each with a role inferred from its name: `vcpu` (`CPU n/KVM`), `iothread`, `vhost`, or `other`.
- A plain QEMU VM's **taps** are found two ways and merged: `ifname=` on the command line, and the `iff:` line in `/proc/<pid>/fdinfo` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its tap as an inherited fd. A FluxVM record replaces that list with the host interface above.
- BPF maps are keyed by **thread id**. Userspace folds them into a VM through the thread list. A pid that is not a VMM thread rolls up to `_host` as `unattributed` and is never given a made-up VM name.
- An event seen on a traced interface is `guest_attributed` only if that interface belongs to a VM in the current scan.

## The tap program, in detail

It is the only program that touches traffic, so it is the one to understand.

- **TCX, not clsact.** It attaches with TCX (Linux 6.6+), at ingress (frames from the guest) and egress (frames to it), and returns `TCX_NEXT`, never `TCX_PASS`, so anything else on the tap (Cilium, another tool) still runs.
- **Pinned.** Its links and most maps live under `/sys/fs/bpf/shukra/tap/`, which is why isolation outlives the daemon and counters continue across a restart. The pinned maps are `tap_stats`, `tap_policy`, `allow4`, `allow6`, `tap_rate`, `tap_events`, `tap_outcomes`, `tap_handshake_hist`, `tap_timeouts`, for DNS names `tap_dns` (the ring) and `dns_cfg` (the on/off switch), and for TLS names `tap_tls` and `tls_cfg`. `udp_flows`, `pending_syn`, `dns_seen` and `tls_flows` (all LRU, all keyed by values the guest controls), `dns_rate` and `tls_rate` are not pinned, so a restart does not inherit stale flows, in-flight handshakes or de-duplication state.
- **Upgrades.** Maps are loaded by pin name. A new map is a new pin, so an upgrade that only adds maps keeps every existing map and link. Only a change to an existing map's layout forces the old pins to be replaced, with a brief gap that the daemon closes by re-applying recorded isolations. The rule when changing the program is never to change a pinned map's layout: add a new map.
- **Isolation.** A flag in `tap_policy` per interface index. While set, every frame is dropped except ARP, IPv6 neighbour discovery and addresses in the `allow4`/`allow6` LPM tries.
- **Events.** A 56-byte record in a 256 KiB ring, decoded by offset in `internal/observe/tap.go` (asserted at compile time). One per TCP SYN, per new UDP flow and per SYN sent to the guest, at most 200 per tap per second.
- **TLS server names.** For a guest TCP segment whose payload starts a handshake record (`0x16`, version 3.0 to 3.4) carrying a ClientHello (type 1, shorter than 64 KiB), the program checks the flow against a fixed-size LRU (a retransmitted hello is not a second event), applies its own 100-per-second budget per tap, and copies up to 1504 bytes of the payload into a third ring, `tap_tls`, as a 1560-byte record: the header is cleared and `rawlen` says how much of `raw` is the packet's, so nothing left in the ring by an earlier record is ever read. `internal/observe/tls.go` decodes it, in Go, for the same reason as DNS: the server name, ALPN list, version, Encrypted Client Hello and a JA3 fingerprint (only for a whole hello). The length of the copy is built by arithmetic on 64-bit values so the verifier can prove it in bounds. `tls_cfg[0]` switches it off (`shukrad -tls-events=false`), and with it off the program reads no TCP payload at all. See [TLS server names](tap.md#tls-server-names).
- **DNS names.** For a plain query to UDP port 53 the program checks the header (`QR=0`, `OPCODE=0`, one question), hashes the name to announce it once a minute per tap, and copies the first 128 bytes of the question into a second ring, `tap_dns`, as a 176-byte record, on its own 200-per-second budget. It does not decode the name: `internal/observe/dns.go` does, in Go, where a bug cannot upset the verifier and the decoder can be unit-tested. `dns_cfg[0]` switches it off (`shukrad -dns-events=false`), and the daemon sets it on every start because the map is pinned. See [DNS names](tap.md#dns-names).
- **Handshakes.** Each SYN is remembered in `pending_syn` until it is answered. A SYN-ACK or RST that matches counts it accepted or refused and forgets it. A SYN never answered is counted by userspace when the counters are read, after 3 seconds, in its own map (BPF has no timers, and a userspace write to a per-CPU value would race the program's increments).

## State, windows and history

`internal/state` is the in-memory truth the API serves. Counters are cumulative since the program attached, which is honest but misleading for "why is it slow **now**", so the state also keeps history:

- A snapshot of every VM's counters is taken at most every **10 seconds** and kept for **6 minutes**. Drop counts and handshake outcomes are snapshotted beside them.
- **Explain, doctor, and the threshold rules read the difference between now and a snapshot one window ago.** The default window is 60 seconds and the longest is 5 minutes. With less than 20 seconds of history the answer falls back to the lifetime and says so. A counter that went backwards was reset, and reads as what happened since the reset, not as a huge number.
- Whether a program is measuring at all is always a lifetime fact, so a quiet minute is never mistaken for a detached program.
- Events, detections and the flight recorder (4096 events per VM) are bounded. Detections are the last 2048.
- **Events are 2048 in all, but not one queue.** A busy host produces a few kinds by the hundreds a second (a k3s node's connects, slow-block samples), and a plain oldest-first queue lets them push out the rare ones an operator is looking for: a guest's DNS name, a connection made into a VM, a detection. Each kind belongs to a class with a share no other class can take:

  | Class | Kinds | Share |
  |---|---|---|
  | guest | `guest_connect`, `guest_flow`, `guest_inbound`, `guest_dns`, `guest_tls` | 512 |
  | host network | `tcp_connect`, `tcp_retransmit` | 512 |
  | notable | `detection`, `vm_start`, `vm_stop` | 256 |
  | process | `exec`, `exit` | 256 |
  | latency | `block_slow`, `sched_delay` | 256 |
  | other | any kind this build does not know | 256 |

  The shares add up to 2048 and only matter once the list is full. A class may use every slot while nobody else wants them, so a host that produces one kind still keeps 2048 of it. When the list is full, the oldest event of the class **furthest over its share** is dropped, so a class under its share is never the one that loses. Events still come back in `Seq` order, and a poller resuming from the last `Seq` it saw never misses or repeats one that is still held. The tests pin all of this, including that the victim is chosen by share and not by size.

## Detection

Rules live in one YAML file (`-watchlist`), re-read on `SIGHUP`:

- **destinations**: a CIDR watchlist, matched on the address a connect went to, or the peer that connected in.
- **ports**: a port, with `proto` (`tcp`, `udp`, `any`) and `dir` (`out`, `in`, `any`).
- **dns**: a name a guest looked up, by `suffix`, `exact` or `contains`.
- **responses**: what to do when a detection fires (`internal/response`): propose an isolation for a person to approve, or, where the rules are named, do it, under guardrails. See [responses](responses.md).
- **baselines**: what is learned as normal for each VM (`internal/baseline`) and reported once when new; off unless the section is present. See [baselines](baselines.md).
- **exec_allow**: names that may start under QEMU without an alert.
- **thresholds**: a per-VM metric over a window (block p99, run-queue delay, vCPU preemption, retransmits, KVM exit rate and latency, guest drops, connection failures, inbound connections).
- **suppress**: a repeat of the same detection inside a window is held back and counted.

A detection keeps the attribution of the event that caused it, so a rule that fires on something the guest did says the guest did it. Detections go to the API, the console and any configured sink (signed webhook, syslog, JSONL file), each with its own queue so a stuck webhook cannot delay the others.

## Persistence

By default everything is in memory. With `-data-dir`, detections and isolation records are appended to JSONL logs (rolling at 16 MiB), and the recorder is saved every minute and on a clean shutdown. Counters and the event list are not saved: they are read back from the kernel or rebuilt.

**History for past verdicts.** The in-memory history is six minutes, which is right for "why is it slow now". So every 5 minutes (`state.RollEvery`) the daemon also appends one snapshot to `snapshots.jsonl`: per VM the counters summed over its threads, its vCPU threads on their own (only the fields a scheduling verdict reads: on-CPU, wakeup delay and its histogram, preemption and who took the CPU), and per tap what the kernel dropped and what became of its TCP handshakes, each only while its program was measuring. `explain --at` and `incident` read the file on demand (they list the snapshots' times and load only the two they need), so none of it sits in memory. A verdict for a past time is the difference between the snapshot at or before that time and the one a window earlier, built with the same code as a live one, and it says the resolution. The file rolls at 16 MiB like the other logs, so retention is set by size: about a day at ten VMs, less for a bigger fleet. A snapshot is 0600 and, like the event list, names your VMs.

## Privilege and trust

The unit runs as root with six capabilities and a read-only filesystem apart from its data directory:

| Capability | Why |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, raise the map limit |
| `CAP_NET_ADMIN` | load and attach the TCX tap program |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun fds of a QEMU that runs as another user |

No program reads application payloads: they count and sample metadata. The exceptions are the first question of a DNS query to UDP port 53, whose name is recorded unless `-dns-events=false`, and the first segment of a TLS ClientHello, whose server name and fingerprint are recorded unless `-tls-events=false` (a hello is sent before anything is encrypted and holds no application data). See [SECURITY.md](../SECURITY.md).

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
| `internal/identity` | Finds QEMU and FluxVM VMMs, their threads, and the host interface to trace |
| `internal/aggregate` | Turns per-thread maps into per-VM rows, deltas and clones |
| `internal/state` | The in-memory truth, history and the stored-snapshot rollup (`rollup.go`), Explain, incident bundles, [doctor](doctor.md) |
| `internal/detect`, `internal/agent` | Rules, thresholds, suppression, and the loop that applies them |
| `internal/api`, `internal/sink`, `internal/persist` | The HTTP API and metrics, alert sinks, on-disk logs |
| `cmd/shukrad`, `cmd/shukractl` | The daemon and the CLI |
| `web/` | The console |
