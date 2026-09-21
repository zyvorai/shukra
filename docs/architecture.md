# Architecture

Shukra is one privileged daemon on the hypervisor, a CLI and a console that only talk to its API, and seven eBPF programs with 31 attach points between them. This page is how the pieces fit, for someone who has to operate it, extend it, or decide whether to trust it. What each number means is in [signals](signals.md), and who an event is attributed to is in [attribution](attribution.md).

```text
┌───────────────────────────── hypervisor ─────────────────────────────┐
│  VMMs: qemu, cloud-hypervisor, firecracker, fluxvm-hypervisor,       │
│  and what they start.  Guests: untouched, nothing runs inside them   │
│      │ threads, block I/O,                    │ tap, or the host     │
│      │ sockets, syscalls                      │ veth vh*             │
│  ┌───┴─────────────────────────┐  ┌───────────┴───────────────────┐  │
│  │ kvm  sched  block  net  vmm │  │ tap    TCX, per VM interface  │  │
│  │ tracepoints and kprobes     │  │ drops  skb:kfree_skb          │  │
│  │ maps, and rings for events  │  │ maps, rings, pinned in bpffs  │  │
│  └───┬─────────────────────────┘  └───────────┬───────────────────┘  │
│      │ maps read every 2 s, rings as they fill│                      │
│  ┌───┴────────────────────────────────────────┴──────────────────┐   │
│  │ shukrad: identity scan, sampler, ring readers, rules, state,  │   │
│  │ response and policy engines, persistence, API                 │   │
│  └───┬───────────────────────────────┬───────────────────────────┘   │
└──────┼───────────────────────────────┼───────────────────────────────┘
       │ bearer key, HTTP or HTTPS     │ pushed: webhook, syslog,
       │ :30970                        │ or a JSONL file
  shukractl   console   Prometheus     alert sinks
```

The CLI, the console and Prometheus are ordinary clients of the [API](api.md): none of them touches the kernel, `/proc` or the data directory. The console is a static build that `shukrad` serves from `-web` (default `web/dist`); it holds the bearer key in memory for one page load.

## The programs

| Program | Attaches to | Keeps | Notes |
|---|---|---|---|
| `kvm` (4 hooks) | `kvm_exit`, `kvm_entry`, `kvm_mmio`, `kvm_pio` | Per-thread exit counts by reason, entry counts, exit-handling time as a log2 histogram and time per reason | Hand-laid tracepoint records, because KVM records are not in vmlinux BTF on 6.8. `kvm_pio` does not exist on arm64 |
| `sched` (4) | `sched_switch`, `sched_wakeup`, `sched_process_exec`, `sched_process_exit` | On-CPU time, run-queue delay and vCPU preemption (runnable but off CPU, and who took it) per thread, and a `watched` set of VMM thread groups | Exec and exit events are filtered in the kernel to a watched VMM and its direct children. Wakeups slower than 20 ms also become events, for any task on the host |
| `block` (2) | `block_rq_issue`, `block_rq_complete` | Latency histogram, bytes and requests per direction, slowest request | Attributed to the task that dispatched the request, which is not always the QEMU thread. Requests of 10 ms or more also become events |
| `net` (3) | `tcp_v4_connect`, `tcp_v6_connect`, `tcp_retransmit_skb` | Exact connect counts; 1 in 64 retransmits become events | The VMM's own sockets. Never the guest. The attribution string is still `qemu-process`. The kprobes fire for every process on the host, and every connect is an event; what no VM owns is `_host` |
| `vmm` (15) | `syscalls:sys_enter_openat`, `openat2`, `open`, `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`, and `sched:sched_process_fork` and `sched_process_exit` to keep the table of descendants | Nothing but a ring of events: a file opened, or a call made, by a VMM process or by something that descends from one | Fires for every process on the host, so it first finds out whether the caller is a VMM (`vmm_watched`), or descends from one (`vmm_desc`, an LRU filled at fork, so lineage survives a parent's exit), or is a process already running that a walk through up to three `real_parent`s finds; only then does it read the path. A per-VMM limit of 300 a second, and a report of how many went over. Paths are judged in the daemon. `-vmm-tripwires=false` does not load it. See [VMM tripwires](vmm-tripwires.md) |
| `drops` (1) | `skb:kfree_skb` | Per VM tap and drop reason: a count and the kernel function that freed the packet | Filters to VM taps first (`drop_watch`). Reads the record by field name (CO-RE). Needs Linux 5.17. See [drops](drops.md) |
| `tap` (2, per interface) | TCX ingress and egress on each VM's host interface (Linux 6.6+) | Counters, TCP handshake outcomes, isolation and egress policy, three event rings (connects and flows, DNS names, TLS names) | The only program that sees the guest's traffic. On FluxVM's default netns the interface is the host veth, not the inner tap. See [guest traffic](tap.md) |

The hooks add up to 31: 4 + 4 + 2 + 3 + 15 + 1 + 2. The `tap` pair is attached once per VM interface, so the count of TCX links follows the VMs.

Each program loads on its own, and a hook that fails to attach does not stop the others in its program or any other program. A host without a KVM tracepoint still gets scheduler, block and network data. When some hooks of a program fail, its status is `attached` with a detail such as `14/15 hooks` and the last error; when none attach it is `detached` with the reason. `tap` is loaded once and attached per VM interface, so it comes and goes with the VMs and its status changes at runtime. `shukractl programs` and `GET /api/v1/programs` show all seven, and `shukra_program_attached` is the same in Prometheus.

The `sched` program's preemption tables (`preempt_start`, `preempt_by`) are small LRUs that only watched threads ever enter; the per-thread totals in `sched_stats` are the exact ones. See [vCPU preemption](signals.md#vcpu-preemption).

**Hot paths stay in maps.** Counters and histograms are BPF maps that userspace reads on a timer. The rings carry discrete events only (an exec, a connect, a slow request, a guest's DNS name), and every producer is filtered in the kernel, thresholded, sampled or rate-limited. The loosest are `net`, which reports every connect by any process on the host, and the slow-request thresholds of `sched` (20 ms) and `block` (10 ms), which apply to every task. A ring is fixed-size: when it is full the kernel drops the new event and the counters, which are in maps, are unaffected. An event lost that way is not counted; the `lost=` figure on a program's status counts records userspace could not read or decode.

## How each program's data reaches you

The path is the same shape for all of them: the kernel side writes maps and rings, the daemon's refresh reads the maps, a ring reader per ring decodes events, `internal/state` holds the result, and the API, the CLI, the console, `/metrics`, the rules and [Explain](signals.md#what-explain-reads) all read `internal/state`.

| Program | Maps (key, size) | Ring | Read by | Surfaces |
|---|---|---|---|---|
| `kvm` | `kvm_exits`, `kvm_reason_ns` (thread id and reason, LRU 16,384), `kvm_lat` (thread id and bucket, LRU 16,384), `kvm_entries`, `kvm_mmio`, `kvm_pio` and `kvm_exit_start` (thread id, LRU 8,192) | none | `observe.Sample`, every 2 s | `trace kvm`, `shukra_kvm_*`, the KVM thresholds, the `kvm_exit_handling` finding, and the advisor (halt time) |
| `sched` | `sched_stats`, `wakeup_ts`, `sched_hist` (thread id, LRU 65,536 each), `preempt_start`, `preempt_by` (LRU 16,384), `watched` (hash, 4,096) | `events` (1 MiB): `exec`, `exit`, `sched_delay` | Sample, in batches; the ring reader | `trace sched`, `trace contention`, `shukra_sched_*`, the run-queue and preemption thresholds, findings `host_cpu_contention`, `cpu_preempted`, `noisy_neighbour`, the advisor, and the events |
| `block` | `blk_inflight` (device and sector, LRU 16,384), `blk_hist` (LRU 65,536), `blk_io` (LRU 16,384), `blk_issues` (LRU 8,192) | `events` (1 MiB): `block_slow` | Sample; the ring reader | `trace block`, `shukra_block_*`, the block thresholds, the `storage_latency` finding |
| `net` | `net_connects`, `net_retrans` (thread id, LRU 8,192 each) | `events` (1 MiB): `tcp_connect`, `tcp_retransmit` | Sample; the ring reader | `trace net`, `shukra_tcp_*`, the `destinations` and `ports` rules on host connects, the `tcp_retransmits` finding |
| `vmm` | `vmm_watched` (hash, 4,096), `vmm_desc` (LRU 8,192), `vmm_rate` (LRU 1,024) | `vmm_events` (256 KiB): `vmm_file_open`, `vmm_syscall` | `SetWatched` writes `vmm_watched`; the ring reader | Events, and the detections `vmm-sensitive-open`, `vmm-syscall`, `vmm-flood`. No counters and no trace command |
| `drops` | `drop_watch` (ifindex, hash, 1,024), `drop_stats` (ifindex and reason, per-CPU hash, 4,096) | none | `DropSample`, when state asks | `trace drops`, `shukra_tap_kernel_drops_total`, findings `guest_traffic_dropped` and `guest_not_reading_nic` |
| `tap` | The pinned maps below, all per interface (ifindex) or per flow | `tap_events`, `tap_dns` (256 KiB each), `tap_tls` (1 MiB) | `TapSample`, when state asks (it first counts unanswered SYNs); three ring readers | `trace tap`, `shukra_tap_*` and `shukra_egress_*`, isolation, egress policy, the `guest_*` events, baselines, and the `guest_connects_failing` finding |

Two consequences worth knowing. First, the `kvm`, `sched`, `block` and `net` maps are read in one pass by `observe.Sample`; the `tap` and `drops` counters are read separately, through `internal/state`, on each refresh (the guest-traffic thresholds need them), on each history snapshot and on each API request. Every read is a fresh sample, and a `tap` read first counts the SYNs nobody answered. Second, a `sched` or `kvm` number is per **host thread id** and only becomes a VM's number in userspace, through the thread table the scan builds.

## The daemon

`shukrad` is a set of goroutines around one shared `internal/state`, guarded by one lock, with file and kernel I/O done outside it.

| Goroutine | Runs | Does |
|---|---|---|
| Refresh loop | every 2 s | The cycle below |
| Ring readers | from the first refresh, one per ring | `events` of `sched`, `block` and `net`, then `tap_events`, `tap_dns`, `tap_tls`, and `vmm_events`: read a record, decode it by offset, and hand it to `Ingest`. A record that does not decode is counted lost, never guessed at |
| Response engine | a 5 s tick, plus a queue of 256 detections | Turns detections into proposals or actions under the guardrails, lets proposals lapse, and releases timed isolations. See [responses](responses.md) |
| Policy engine | every 2 s | `Reconcile`: reverts an egress policy whose timer ran out, and makes the kernel match the record on every tap of every VM. See [egress policy](egress-policy.md) |
| Persistence | every minute, with `-data-dir` only | Rewrites `recorder.json`, prunes and saves `baselines.json` |
| Sink workers | one per sink (webhook, syslog, file), each with a queue of 256 | Deliver detections. A stuck webhook cannot delay the others, and a full queue drops for that sink only, counted |
| `SIGHUP` handler | on the signal | Reloads the TLS certificate and the rules file. A bad one is logged and the previous one stays in force |
| HTTP server | per request | The API, `/metrics`, the event stream (a keepalive every 15 s) and the console |

**One refresh, in order.**

1. `identity.Scan` walks `/proc`. If the walk fails the cycle ends and the previous state stands.
2. The VM list is stored. A VM that appears is a `vm_start` event, and one missing for two scans in a row is a `vm_stop`, so one bad read is not a stop and a start. The first scan is silent.
3. `SetWatched` makes the `sched` `watched` set and the `vmm` `vmm_watched` set equal to the VMM thread groups found, adding and removing. A child that starts in the first couple of seconds after a VM appears can be missed by the exec filter.
4. `SetThreads` gives userspace the table from thread id to VM and role, which is how per-thread maps become per-VM rows.
5. `SyncTaps` attaches the `tap` program to each VM's interface and takes it off any that are gone, and keeps the `drops` program's `drop_watch` equal to the same set.
6. Recorded isolations are re-applied to any tap that lacks the flag (a restart, a VM that came back with a new tap).
7. Program status is stored. The first time, this is what makes `/readyz` answer 200.
8. `observe.Sample` reads the `kvm`, `sched`, `block` and `net` maps and the counters are stored, which takes a history snapshot (at most every 10 s) and, with `-data-dir`, a stored snapshot (every 5 minutes). Then the threshold rules run on them, reading the `tap` and `drops` counters for the guest-traffic metrics.
9. Ring readers are started, once each.

The policy engine's own pass runs on its own 2-second tick, and startup does one `Refresh` and one `Reconcile` at once, so a policy timer that ran out while the daemon was down reverts before the first tick.

**Shutdown.** The API stops (3 seconds to finish requests), the tap program is detached from every tap that is not isolated or enforcing an egress policy, the sinks drain (up to 5 seconds), the engines stop, baselines are saved, and a final recorder snapshot is written. A crash skips all of that, which is what pinning is for.

**Cost.** On a production hypervisor (12 cores, 10 VMs, a k3s and Cilium node) profiling found the daemon using about 55% of a core, nearly all of it garbage collection. Three changes brought it to 5 to 9% of a core with the same output ([CHANGELOG](../CHANGELOG.md)): the flight recorder is a real ring (adding to a full one allocates nothing), the scheduler counters of threads no VM owns are summed into one host slot as they are read instead of one row each, and the large maps are read in batches of up to 2,048 entries (with a fallback to the old walk on a kernel or map that cannot batch).

## Identity: joining a number to a VM

Identity comes from the host, never from inside the guest.

- `identity.Scan` walks `/proc` every 2 seconds. A `qemu-system*` process is read from its command line: `-name` or `guest=`, `-uuid`, `ifname=`. `libvirt` and `kubevirt` are labels derived from that command line, not a guest agent.
- When FluxVM is installed, the same scan reads `{state_dir}/vms.json` (`state_dir` from `/etc/fluxvm.toml`, otherwise `/var/lib/fluxvm`). Each record with a live pid is a VM: QEMU pids already found are updated, and `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor` are added. `runtime` is `fluxvm`. The name and UUID come from the record, because FluxVM's QEMU argv has neither `-name` nor `-uuid`. A missing store is ignored.
- The interface traced is, in order, `/run/fluxvm/ebpf/vms/<id>/iface` if FluxVM wrote one, else the host veth `vh` plus the first 8 hex digits of the id when `netns` is set, else `tap_name`. The inner `tap<8hex>` of a per-VM netns is not kept. Detail, including why ingress on that veth is "from the guest", is in [FluxVM](tap.md#fluxvm).
- A VM's **threads** come from `/proc/<pid>/task`, each with a role inferred from its name: `vcpu` (`CPU n/KVM`), `iothread`, `vhost`, or `other`.
- A plain QEMU VM's **taps** are found two ways and merged: `ifname=` on the command line, and the `iff:` line in `/proc/<pid>/fdinfo` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its tap as an inherited fd. A FluxVM record replaces that list with the host interface above.
- BPF maps are keyed by **thread id**. Userspace folds them into a VM through the thread list. A pid that is not a VMM thread rolls up to `_host` as `unattributed` and is never given a made-up VM name.
- An event seen on a traced interface is `guest_attributed` only if that interface belongs to a VM in the current scan.
- A VM is named by what the host says, and baselines and policies are keyed by that name, so two VMs given the same name would share a row of each.

## The tap program, in detail

It is the only program that touches traffic, so it is the one to understand.

- **TCX, not clsact.** It attaches with TCX (Linux 6.6+), at ingress (frames from the guest) and egress (frames to it), and returns `TCX_NEXT`, never `TCX_PASS`, so anything else on the tap (Cilium, another tool) still runs. It attaches at the default position: nothing orders it against another TCX program. Kernels older than 6.6 leave the program detached. That is a failed attach. Host probes still run. There is no classic tc fallback.
- **A new link is not waited on.** `RTM_NEWLINK` and `RTM_DELLINK` run the same tap sync as the two-second scan, then the saved egress policy, before the tap is reported as covered. A missed notification is caught by the scan. An enforcing VM with a live tap and no program raises `tap-uncovered`. `-quarantine-uncovered` is off: it would drop that tap, except the management allow list, until the policy is written.
- **Pinned.** Its links and 16 maps live under `/sys/fs/bpf/shukra/tap/`, which is why isolation outlives the daemon and counters continue across a restart. The links are `link-<interface>-in` and `link-<interface>-out`. The pinned maps are `tap_stats`, `tap_policy`, `allow4`, `allow6`, `tap_rate`, `tap_events`, `tap_outcomes`, `tap_handshake_hist`, `tap_timeouts`, for DNS names `tap_dns` (the ring) and `dns_cfg` (the on/off switch), for TLS names `tap_tls` and `tls_cfg`, and for the egress policy `egress4`, `egress6` (one trie each for every VM's list) and `egress_stats`. The policy's mode per tap is the second byte of the existing `tap_policy` value, which always had seven spare, so that map's layout is what it was. `udp_flows`, `pending_syn`, `dns_seen`, `tls_flows` and `egress_udp_in` (all LRU, all keyed by values the guest controls), `dns_rate` and `tls_rate` are not pinned, so a restart does not inherit stale flows, in-flight handshakes or de-duplication state. Without a bpf filesystem at `/sys/fs/bpf` nothing is pinned, the status says so, and isolation lasts only while the daemon runs.
- **Upgrades.** Maps are loaded by pin name. A new map is a new pin, so an upgrade that only adds maps keeps every existing map and link. Only a change to an existing map's layout forces the old pins to be replaced, with a brief gap that the daemon closes by re-applying recorded isolations. The rule when changing the program is never to change a pinned map's layout: add a new map.
- **Isolation.** A flag in `tap_policy` per interface index. While set, every frame is dropped except ARP, IPv6 neighbour discovery and addresses in the `allow4`/`allow6` LPM tries (256 entries each). Isolate is refused without a management allow list.
- **Events.** A 56-byte record in a 256 KiB ring, decoded by offset in `internal/observe/tap.go` (asserted at compile time). One per TCP SYN, per new UDP flow and per SYN sent to the guest, at most 200 per tap per second.
- **Egress policy.** A tap whose `tap_policy.egress` is not off judges what its guest starts: a TCP SYN, or a UDP datagram that is neither multicast nor an answer to one that came in (the LRU `egress_udp_in`, refreshed by each datagram sent to the guest). A destination is inside if it is on the management allow list (`allow4`/`allow6`, which no policy can take away) or on the VM's own list, held in `egress4`/`egress6` (16,384 networks in all, and the daemon accepts 1,024 per VM) with the ifindex inside the key so one trie serves every VM. Audit counts what would be dropped and lets it through; enforce sets `drop` before the handshake is followed, so the drop counts as Shukra's own everywhere isolation's does. The verdict travels on the connect event in a spare byte, so its layout is unchanged. What is put there, when, and how it is reverted is `internal/policy`. See [egress policy](egress-policy.md).
- **TLS server names.** For a guest TCP segment whose payload starts a handshake record (`0x16`, version 3.0 to 3.4) carrying a ClientHello (type 1, shorter than 64 KiB), the program checks the flow against a fixed-size LRU (a retransmitted hello is not a second event), applies its own 100-per-second budget per tap, and copies up to 1504 bytes of the payload into a third ring, `tap_tls` (1 MiB), as a 1560-byte record: the header is cleared and `rawlen` says how much of `raw` is the packet's, so nothing left in the ring by an earlier record is ever read. `internal/observe/tls.go` decodes it, in Go, for the same reason as DNS: the server name, ALPN list, version, Encrypted Client Hello and a JA3 fingerprint (only for a whole hello). The length of the copy is built by arithmetic on 64-bit values so the verifier can prove it in bounds. `tls_cfg[0]` switches it off (`shukrad -tls-events=false`), and with it off the program reads no TCP payload at all. See [TLS server names](tap.md#tls-server-names).
- **DNS names.** For a plain query to UDP port 53 the program checks the header (`QR=0`, `OPCODE=0`, one question), hashes the name to announce it once a minute per tap, and copies the first 128 bytes of the question into a second ring, `tap_dns`, as a 176-byte record, on its own 200-per-second budget. It does not decode the name: `internal/observe/dns.go` does, in Go, where a bug cannot upset the verifier and the decoder can be unit-tested. `dns_cfg[0]` switches it off (`shukrad -dns-events=false`), and the daemon sets it on every start because the map is pinned. See [DNS names](tap.md#dns-names).
- **Handshakes.** Each SYN is remembered in `pending_syn` until it is answered. A SYN-ACK or RST that matches counts it accepted or refused and forgets it. A SYN never answered is counted by userspace when the counters are read, after 3 seconds, in its own map (BPF has no timers, and a userspace write to a per-CPU value would race the program's increments).

## State, windows and history

`internal/state` is the in-memory truth the API serves. Counters are cumulative since the program attached, which is honest but misleading for "why is it slow **now**", so the state also keeps history:

- A snapshot of every VM's counters is taken at most every **10 seconds** and kept for **6 minutes**. Drop counts and handshake outcomes are snapshotted beside them.
- **Explain, contention, the advisor, doctor and the threshold rules read the difference between now and a snapshot one window ago.** The default window is 60 seconds and the longest is 5 minutes (the advisor defaults to 5). With less than 20 seconds of history the answer falls back to the lifetime and says so. A counter that went backwards was reset, and reads as what happened since the reset, not as a huge number.
- Whether a program is measuring at all is always a lifetime fact, so a quiet minute is never mistaken for a detached program.
- Events, detections and the flight recorder are bounded. The recorder keeps 4,096 events per VM name (a fixed ring for each name seen since the daemon started, and one for `_host`), detections are the last 2,048, and so are the recorded isolations.
- **Events are 2048 in all, but not one queue.** A busy host produces a few kinds by the hundreds a second (a k3s node's connects, slow-block samples), and a plain oldest-first queue lets them push out the rare ones an operator is looking for: a guest's DNS name, a connection made into a VM, a detection. Each kind belongs to a class with a share no other class can take:

  | Class | Kinds | Share |
  |---|---|---|
  | guest | `guest_connect`, `guest_flow`, `guest_inbound`, `guest_dns`, `guest_tls` | 512 |
  | host network | `tcp_connect`, `tcp_retransmit` | 512 |
  | notable | `detection`, `vm_start`, `vm_stop` | 256 |
  | process | `exec`, `exit`, `vmm_file_open`, `vmm_syscall` | 256 |
  | latency | `block_slow`, `sched_delay` | 256 |
  | other | any kind this build does not know | 256 |

  The shares add up to 2048 and only matter once the list is full. A class may use every slot while nobody else wants them, so a host that produces one kind still keeps 2048 of it. When the list is full, the oldest event of the class **furthest over its share** is dropped, so a class under its share is never the one that loses. Events still come back in `Seq` order, and a poller resuming from the last `Seq` it saw never misses or repeats one that is still held. The tests pin all of this, including that the victim is chosen by share and not by size.

## Detection

Rules live in one YAML file (`-watchlist`), re-read on `SIGHUP`. It is parsed strictly, so a misspelled section is an error and not a rule that quietly does nothing, and a file that fails to parse leaves the previous rules in force. With no file, the defaults apply: the VMM tripwire rules are built in and everything else is empty.

- **destinations**: a CIDR watchlist, matched on the address a connect went to, or the peer that connected in.
- **ports**: a port, with `proto` (`tcp`, `udp`, `any`) and `dir` (`out`, `in`, `any`).
- **dns**: a name a guest looked up, by `suffix`, `exact` or `contains`.
- **tls**: a server name in a guest's ClientHello, matched the same three ways. `dns` and `tls` rules do not judge each other's names.
- **responses** and **guardrails**: what to do when a detection fires (`internal/response`): propose an isolation for a person to approve, or, where the rules are named, do it, under guardrails. See [responses](responses.md).
- **baselines**: what is learned as normal for each VM (`internal/baseline`) and reported once when new; off unless the section is present. See [baselines](baselines.md).
- **vmm**: what a VMM process tree may not open or call (`internal/detect/vmm.go`), with built-in defaults that need no section: sensitive paths (`*` is one segment, a match is the path and all beneath it), paths to ignore, and which calls to report. See [VMM tripwires](vmm-tripwires.md).
- **exec_allow**: names that may start under QEMU without an alert.
- **thresholds**: a per-VM metric over a window (block p99, run-queue delay, vCPU preemption, retransmits, KVM exit rate and latency, guest drops, connection failures, inbound connections).
- **suppress**: a repeat of the same detection inside a window (5 minutes by default) is held back and counted. The table of keys holds 4,096 and, if it is full of live keys, lets the detection through unrecorded: it fails toward alerting.

A detection keeps the attribution of the event that caused it, so a rule that fires on something the guest did says the guest did it. Detections Shukra raises about its own state (`action-*`, `policy-*`, thresholds) name the VM but are not guest-attributed. Detections go to the API, the console and any configured sink (signed webhook, syslog, JSONL file), each with its own queue so a stuck webhook cannot delay the others.

## Acting on a VM

Three things can change what a VM may do, and each is built so that the record is never behind the kernel and a person can always get back.

| | What it does | How it is guarded | Where it lives |
|---|---|---|---|
| **Isolate** (`shukractl isolate`) | Drops the VM's tap traffic except the management allow list | Refused without `-isolate-allow`, for an unknown VM, a VM with no tap, or without the tap program. `applied` is true only after the kernel took it on every tap. Admin key | Flag in the pinned `tap_policy`; recorded in `isolations.jsonl` and re-applied if the kernel lost it |
| **Response** (`responses:` in the rules) | Proposes an isolation on a detection, or does it on its own for named rules | Proposes by default. Guardrails on every one: `never_isolate`, isolate must work, `max_per_hour` (3 by default) automatic isolations, a per-VM `cooldown`, proposal `expire`, a timed `release_after` that survives a restart. Approve and reject need the admin key, and re-check the guardrails | `actions.jsonl`, and the incident bundle each was decided on |
| **Egress policy** (`shukractl policy`) | Drops what a VM starts outside a list of networks | Off until applied. Audit first, and audit needs nothing. Enforcing needs the management allow list, `-data-dir`, a non-empty list, and `--confirm` (a timer that reverts it) or `--permanent`. A change the kernel refuses is put back | `policies.json`, saved before the kernel is changed; pinned `egress4`, `egress6`, and the mode byte in `tap_policy` |

All three are announced as detections, so a webhook hears of them. The kernel keeps enforcing without the daemon, which is why a lost record is a finding (an **orphan**, in `shukractl doctor`) and not something the daemon guesses about.

## Persistence

By default everything is in memory. With `-data-dir` (the shipped unit uses `/var/lib/shukra`), these files are kept. The directory is created `0700` and every file is `0600`, because they name your VMs, their addresses and the names they looked up.

| File | Written | Held | Read back at start |
|---|---|---|---|
| `detections.jsonl` | On every detection | Rolls to `detections.jsonl.1` at 16 MiB, replacing the older `.1`, so disk use is near twice that | The newest 2,048 |
| `isolations.jsonl` | On every isolate or release request, and by `-detach-all` | Same, 16 MiB and a `.1` | The newest 2,048. What it says is active is re-applied to the kernel |
| `recorder.json` | Every minute, and on a clean shutdown, replaced whole and synced | One document; up to 4,096 events per VM | The per-VM flight recorder. After a crash it can be a minute behind |
| `snapshots.jsonl` | Every 5 minutes | Rolls at 16 MiB with a `.1`, so retention is set by size, not time | Not loaded: read on demand by `explain --at` and `incident` |
| `actions.jsonl` | On every decision a response makes (the last record of an id is the truth) | Rolls at 16 MiB with a `.1` | The newest 2,000 records, of which the engine keeps 500 actions. Pending proposals lapse on time and timed isolations release on time |
| `incidents/a-<n>.json` | With each action | The newest 200 files | Read on demand by `shukractl actions --bundle` |
| `baselines.json` | Every minute if it changed, and on shutdown | Items unseen for `max_age` (30 days by default) are pruned each minute; 2,048 items per kind per VM | What each VM has learned, so a restart does not restart the learning |
| `policies.json` | On every policy change, replaced whole and synced | One document | Each VM's policy and any timer waiting to be confirmed. A file that cannot be read is set aside as `policies.json.corrupt` and the taps it named are reported as orphans |

The `actions.jsonl` and `incidents/` entries exist only once responses are configured and act; the directory is created either way. A crash can tear the last line of a log: the next start ends it, and a line that does not decode is skipped. A corrupt `baselines.json` costs the learning and never the daemon. `shukrad` refuses to start if `-data-dir` cannot be opened, so it never runs believing it is keeping records that it is not.

Counters and the event list are not saved: they are read back from the kernel or rebuilt. Also outside the data directory, in `/sys/fs/bpf/shukra/tap/`, are the tap program's pinned maps and links, which is what outlives the daemon.

**History for past verdicts.** The in-memory history is six minutes, which is right for "why is it slow now". So every 5 minutes (`state.RollEvery`) the daemon also appends one snapshot to `snapshots.jsonl`: per VM the counters summed over its threads, its vCPU threads on their own (only the fields a scheduling verdict reads: on-CPU, wakeup delay and its histogram, preemption and who took the CPU), and per tap what the kernel dropped and what became of its TCP handshakes, each only while its program was measuring. `explain --at` and `incident` read the file on demand (they list the snapshots' times and load only the two they need), so none of it sits in memory. A verdict for a past time is the difference between the snapshot at or before that time and the one a window earlier (the window is 5 minutes to 6 hours, 15 minutes by default), built with the same code as a live one, and it says the resolution. The file rolls at 16 MiB like the other logs, and the rolled `.1` is read too, so retention is set by size and lies between one file's worth and two: about a day or two at ten VMs (a snapshot is about 58 KB there, per [after the fact](tutorials/09-after-the-fact.md)), less for a bigger fleet. If no snapshot is stored at or before that time, or the nearest is more than 10 minutes before it, the answer is `no_history` and says why; nothing is guessed. A snapshot is 0600 and, like the event list, names your VMs.

## Trust boundaries

Shukra is built on one assumption about the guest: it controls the bytes it sends and how hard it drives its VMM, and nothing else. It cannot name itself (identity is the host's view of the VMM process), it cannot change what is attributed to it (that comes from which tap the packet crossed), and every table it can influence has a fixed size.

| What a guest, or a VMM it has taken over, controls | Where it lands | How it is bounded |
|---|---|---|
| The flows it opens: addresses and ports | `udp_flows`, `pending_syn`, `egress_udp_in` (LRU, 65,536 each), `dns_seen`, `tls_flows` (LRU, 16,384 each). None is pinned | Fixed-size LRUs: a guest can turn them over, not grow them. A flood of unanswered SYNs makes `pending_syn` forget the oldest uncounted, though `attempts` still counts every one |
| How many events it provokes | `tap_events`, `tap_dns` (256 KiB each), `tap_tls` (1 MiB) | 200, 200 and 100 a second per tap, each on its own budget, so one kind cannot starve another. The counters still see every packet |
| What it names: DNS names, server names, ALPN, fingerprints | Decoded in Go, into events, the recorder, detections and baselines | Every non-printable byte becomes `?`, a name is cut at 253 bytes, lists are bounded, and a hello is decoded again and refused if it claims to be longer than a TLS record. A hello copy is at most 1,504 bytes with its header cleared, and DNS names are announced once a minute per tap and name |
| Which sectors it reads and writes | `blk_inflight`, keyed by device and sector (LRU, 16,384) | Fixed size. Two overlapping requests to one sector collide, and the older is lost from the histogram. That is a limit on accuracy, not on memory |
| How much CPU, block I/O and KVM exit work it causes | Per-thread maps keyed by host thread id (LRU), which the guest does not choose | Fixed size. The `sched` maps are sized for it (65,536), because every task on the host passes `sched_switch` |
| What a VMM process and its descendants open and call (once compromised) | `vmm_desc` (LRU, 8,192), `vmm_rate` (LRU, 1,024), the `vmm_events` ring (256 KiB) | At most 300 reported calls per VMM per second, and a report of how many went over. Deep or wide forking turns `vmm_desc` over and the process is found again through its parents while they live |
| What its events do to the daemon | The event list, the recorder, detections, the suppression table, baselines | The event list is 2,048 with a guaranteed share per class; the recorder is 4,096 per VM; detections are the last 2,048; the suppression table is 4,096 keys and fails toward alerting; a VM's baseline is at most 2,048 items per kind and 20 new-item alerts a day; an egress policy may list 1,024 networks |
| Names and addresses that end up on disk | `detections.jsonl`, `recorder.json` and the rest of the data directory | The files are `0600` in a `0700` directory. What is read back is normalised again, so a hand-edited file cannot claim guest attribution. The directory is on the built-in sensitive-path list, so a VMM that opens `/var/lib/shukra` or `/etc/shukra` is a critical detection |

What Shukra does **not** defend against: a VMM that has been compromised can change its own command line, so what a scan reads from `/proc` is its word; that is the case the `vmm` program watches for, and it is a tripwire and not a sandbox. Nothing here protects a host from root on the host.

**The API is the other boundary.** `/healthz`, `/readyz` and the console's page and assets are open. Everything else, `/metrics` and the event stream included, needs `Authorization: Bearer`. The admin key may do everything; `SHUKRA_READONLY_KEY` may only `GET`, and must differ from the admin key or the daemon refuses to start. Both keys are compared in constant time. The admin key is needed for isolate, release, forget, approve, reject and the policy changes, and request bodies are read to at most 64 KiB (1 MiB for a policy).

### Fail closed

When something is missing or wrong, the daemon does less and says so; it does not do more, and it does not invent.

- **No program, no number.** Without root, clang, BTF or a new enough kernel a program reports `detached` with the reason, a VM whose program is not measuring has no series at all ("not measured", never zero), and the stub build serves discovered VMs and reports every program detached. It never invents a counter.
- **No key, no API.** An empty admin key matches nothing. The well-known dev key `shukra` exists only when `SHUKRA_API_KEY` is unset, is announced at start, and is a failure in `shukractl doctor` on a non-loopback address. `-no-auth` is the only way to serve without one, and it warns. Plain HTTP on a non-loopback address warns.
- **No allow list, no isolation.** Isolate and every enforcing policy are refused without `-isolate-allow`, because an isolated VM that could reach nothing could not be reached by the host that isolated it. `applied` is true only after the kernel took the change, and a half-applied change stays contained rather than silently reopening.
- **No record, no enforcing policy.** Enforcing needs `-data-dir`, a non-empty list and a timer or an explicit `--permanent`. The record is saved before the kernel is changed, a change that fails is put back, and a policy nobody has a record of is an orphan, not a guess.
- **A bad rules file changes nothing.** At start it stops the daemon; on `SIGHUP` the previous rules, and the previous responses, stay in force. A bad certificate on `SIGHUP` keeps the current one.
- **A missing or damaged file costs data, not the daemon.** A torn log line is skipped, a corrupt baseline file means learning starts over, a corrupt policy file is set aside, and a missing `-data-dir` file is a first run.
- **Unknown is unattributed.** A tap no VM owns, a pid no VM owns and a kind this build does not know are `unattributed` or `_host` or the `other` class, never a made-up VM or a guest attribution.
- **A stop does not reopen a VM.** A graceful stop and a crash both leave an isolated tap isolated and an enforcing tap enforcing. Only `shukrad -detach-all` lifts them with the daemon down, and with `-data-dir` it records the release so the next start does not re-apply them.
- **A response cannot outrun its guardrails.** It refuses when isolate is unavailable, when the VM is on `never_isolate`, past the hourly cap; a proposal that nobody decides lapses; and an approval checks all of it again.

## Privilege and trust

The unit runs as root with six capabilities and a read-only filesystem apart from its data directory:

| Capability | Why |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, raise the map limit |
| `CAP_NET_ADMIN` | load and attach the TCX tap program |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun fds of a QEMU that runs as another user |

No program reads application payloads: they count and sample metadata. The exceptions are the first question of a DNS query to UDP port 53, whose name is recorded unless `-dns-events=false`; the first segment of a TLS ClientHello, whose server name and fingerprint are recorded unless `-tls-events=false` (a hello is sent before anything is encrypted and holds no application data); and the names of the files a VMM process opens, recorded unless `-vmm-tripwires=false` (the name, never the contents). See [SECURITY.md](../SECURITY.md).

## Kernel requirements

| Feature | Needs |
|---|---|
| Any program | BTF at `/sys/kernel/btf/vmlinux`, and `CAP_BPF` (Linux 5.8+) |
| `vmm` | The `syscalls` and `sched_process_fork` tracepoints. A hook the kernel lacks is skipped and named in the status (`N/15 hooks`) |
| `drops` | Linux 5.17+ (a drop reason on `kfree_skb`) |
| `tap` (guest traffic, handshakes, isolation, egress policy) | Linux 6.6+ (TCX). Older kernels report it detached, and the rest works |
| Isolation and policy that outlive the daemon | A bpf filesystem at `/sys/fs/bpf`. Without one they last only while the daemon runs, and the status says so |
| Reading libvirt VMs' taps | `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` |

A build without root, clang or BTF still serves discovered VMs and reports every program `detached` with the reason. It never invents a counter.

## Where things are

| Path | What |
|---|---|
| `bpf/*.bpf.c`, `bpf/event.h` | The seven programs and the shared event layout |
| `internal/bpfgen` | Loads and attaches them (CO-RE via bpf2go). `tap.go` is the tap manager, `attach.go` the other six |
| `internal/observe` | Reads the maps, decodes events, joins the loaders to the rest. Has a stub for builds without BPF |
| `internal/identity` | Finds QEMU and FluxVM VMMs, their threads, and the host interface to trace |
| `internal/aggregate` | Turns per-thread maps into per-VM rows, deltas and clones |
| `internal/state` | The in-memory truth, history and the stored-snapshot rollup (`rollup.go`), the event classes (`events.go`), Explain, contention, the advisor, incident bundles, [doctor](doctor.md) |
| `internal/detect`, `internal/agent` | Rules, thresholds, suppression, and the loop that applies them |
| `internal/baseline`, `internal/response`, `internal/policy` | Learned baselines, guarded responses, the egress policy engine |
| `internal/recorder` | The per-VM flight recorder |
| `internal/api`, `internal/sink`, `internal/persist` | The HTTP API and metrics, alert sinks, on-disk logs and records |
| `cmd/shukrad`, `cmd/shukractl` | The daemon and the CLI |
| `web/` | The console |
