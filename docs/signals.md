# What each program measures

Six of the seven programs see the **VMM process** from the host (the `vmm` program watches what it and its children open and call, see [VMM tripwires](vmm-tripwires.md)): QEMU, or a FluxVM backend (`cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor`). That is the vCPU and I/O threads, its block requests, its own sockets. The `tap` and `drops` programs see the **guest's traffic** on the host side of its tap, or on the host veth FluxVM uses when the tap is in a per-VM netns. None of it is measured inside the guest: Shukra never runs anything in the VM, so it can say which VM and which address, never which process. See [attribution](attribution.md) and [FluxVM](tap.md#fluxvm).

| Program | Records | Caveat |
|---|---|---|
| `kvm` | Exit counts by reason. **Handling time**: `kvm_exit` to the next `kvm_entry` on the same vCPU thread, as a log2 histogram. Total time per reason | A halt blocks until an interrupt, so its time is guest idle. It is in the per-reason totals and left out of the latency histogram (reason 12 on VMX, 120 on SVM) |
| `sched` | On-CPU time. **Run-queue delay** (wakeup to running) as a log2 histogram, per task. **vCPU preemption**: time a vCPU thread was runnable but off a host CPU, and who had it | Per VMM thread with `?threads=1`, so a slow vCPU is distinguishable from a slow iothread |
| `block` | Completed requests, bytes, slowest request, and a log2 latency histogram, per direction | It is the QEMU I/O thread, not the guest filesystem. The slowest request is updated without a lock, so two CPUs racing can miss a slightly smaller maximum |
| `tap` | Per-tap packets and bytes each way and what isolation dropped, from TCX on the VM's host interface. **What became of each TCP handshake**, both ways: accepted, refused, never answered, blocked by isolation, and retransmits, plus the time to be answered as a log2 histogram. A `guest_inbound` event per connection made to the guest. A `guest_connect` event per TCP SYN and a `guest_flow` event per new UDP flow, capped at 200 per tap per second | The only program that sees the guest. Needs Linux 6.6+. On FluxVM's default netns the interface is `vh<8hex>`, and the guest address is the one before NAT. See [Guest traffic and isolation](tap.md) |
| `drops` | What the kernel dropped on each VM tap, counted by the kernel's own reason (`skb:kfree_skb`): TC_INGRESS, TC_EGRESS, FULL_RING and the rest, and the kernel function that freed the last one | Only the VM taps are counted. Shukra's own isolation drops appear as TC_INGRESS or TC_EGRESS, so they are subtracted using the tap program's `dropped` count: what is left is **someone else's**. A full queue (FULL_RING) is the guest not reading its NIC, and is reported on its own. The kernel function that freed them is named by the kernel itself (`bpf_snprintf` `%ps`, once when a reason is first seen on a tap), so it needs no capability; it is the function at the first free seen, and if the kernel cannot name it, `/proc/kallsyms` is tried and then the address is shown. Reason names come from this kernel's BTF, and an unknown reason is shown as its number |
| `net` | `tcp_v4_connect` and `tcp_v6_connect`, counted exactly in a kernel map. 1 in 64 retransmits become events, IPv4 and IPv6 | A dual-stack socket connecting to a v4-mapped address is counted once, by the IPv4 probe |

## Events

`exec` and `exit` are emitted only for a watched VMM and its children, not for every process on the host. The watched set is every `qemu-system*` pid and every live FluxVM VMM pid. `shukrad` tells the kernel which processes those are through a `watched` map, refreshed on each scan, so a child that starts in the first couple of seconds after a VM appears can be missed. Each event carries the parent's tgid from the kernel, which is how a short-lived child is still joined to its VM after it has gone. An unrelated parent stays unattributed.

Without that filter, 300 runs of `/bin/true` produced 330 exec and 328 exit events on a test host. That would be enough to push connects and detections out of the 2048-event list within seconds on a busy hypervisor, which is why the filter exists, and why the list keeps a share for each kind of event so no one kind can take the rest.

The daemon holds the newest 2048 events, but with a **guaranteed share for each kind** (guest events 512, host connects 512, and 256 each for detections and VM start and stop, process events, latency samples and anything unknown), so a flood of one kind cannot push out a rare one. The shares only matter once the list is full, and are in [architecture](architecture.md#state-windows-and-history).

## Guest traffic signals

These come from the tap program and the drops program, and are the only ones that are `guest_attributed`. Details are in [guest traffic and isolation](tap.md) and [where packets die](drops.md); the meaning of each number, in one place:

- **`out` and `in`.** `out` is the guest's own connections. `in` is connections made **to** the guest.
- **Attempts, and what became of them.** An attempt is a new SYN. It ends as **accepted** (a SYN-ACK), **refused** (an RST), **never answered** (`timed_out` outbound, `ignored` inbound; nothing within 3 seconds) or **blocked** (isolation dropped it). A repeat of the same SYN is a **retransmit**, not a new attempt. So attempts = accepted + refused + never answered + blocked, plus any still waiting. This identity is asserted exactly by the tap rig.
- **Handshake time** is SYN to SYN-ACK of the guest's accepted outbound connections, as a log2 histogram, seen at the host's tap.
- **Kernel drops** are what the kernel dropped on the tap, by its own reason. Shukra's isolation shows as `TC_INGRESS`/`TC_EGRESS` and is subtracted, a full queue (`FULL_RING`) is a guest not reading its NIC, and the rest is `other`.
- **DNS names.** `guest_dns` events carry the first question of a UDP/53 query. They are announced once a minute per tap, name and type, and are not counters: there is no series for them. They are omitted entirely under `-dns-events=false`.
- **TLS server names.** `guest_tls` events carry the server name, protocols, version and fingerprint of a ClientHello. One per connection (a retransmitted hello is not another), at most 100 a second per tap, and not counters: there is no series for them. They are omitted entirely under `-tls-events=false`.
- **Windows.** Explain, doctor and the threshold rules read these over the last minute, not the life of the daemon.

## Latency is bucketed

`p50`, `p99` and the histograms come from log2 buckets: bucket `i` counts values below `2^(i+1)` ns. A percentile is the top edge of its bucket, so it can read up to 2x high. The raw buckets are in the API (`readHist`, `writeHist`, `exitLatencyHist`, `wakeupHist`) and drawn in the console with the same caveat printed under each chart.

## Exit reason names

Reasons are named only on Intel hosts, from the SDM's basic exit reasons. AMD numbers its exit codes differently and reuses small values for other things, and arm64 reports an exception class, so those hosts show the raw number and no name. A name is never guessed.

## Prometheus

`/metrics` needs the bearer key. Latency is exposed as real histograms so percentiles are over a window you choose, not since the daemon started:

```promql
# p99 block write latency per VM over 5 minutes
histogram_quantile(0.99, sum by (le, vm) (rate(shukra_block_latency_seconds_bucket{op="write"}[5m])))

# host time per second spent on each kind of KVM exit, excluding guest idle
sum by (vm, name) (rate(shukra_kvm_exit_handling_seconds_total{name!="hlt"}[5m]))

# run-queue delay p99
histogram_quantile(0.99, sum by (le, vm) (rate(shukra_sched_runqueue_delay_seconds_bucket[5m])))
```

There is no `_sum` series. The kernel keeps buckets, not a total, and a sum built from bucket midpoints would be invented. The bucket set is fixed (`le` from 128 ns to about 137 s, then `+Inf`), so a series keeps the same buckets from scrape to scrape. A VM whose program is not measuring has no series at all, which means "not measured", not zero.

| Series | Type and labels |
|---|---|
| `shukra_vms` | gauge. QEMU VMs found in the last scan |
| `shukra_program_attached` | gauge, `program` (`kvm`, `sched`, `block`, `net`, `tap`, `drops`). 1 when attached |
| `shukra_events_total` | counter. Discrete events stored since the daemon started |
| `shukra_detections`, `shukra_detections_suppressed_total` | gauge held; counter of repeats held back |
| `shukra_alert_sent_total`, `shukra_alert_failed_total`, `shukra_alert_dropped_total` | counter, `sink` |
| `shukra_kvm_exits_total` | counter, `vm` |
| `shukra_kvm_exits_by_reason_total` | counter, `vm`, `reason`, `name` (Intel only) |
| `shukra_kvm_exit_handling_seconds_total` | counter, `vm`, `reason`, `name`. A halt's time is guest idle |
| `shukra_kvm_exit_latency_seconds` | histogram, `vm` |
| `shukra_sched_on_cpu_seconds_total`, `shukra_sched_wakeup_delay_seconds_total` | counter, `vm` |
| `shukra_sched_runqueue_delay_seconds` | histogram, `vm` |
| `shukra_sched_vcpu_preempted_seconds_total` | counter, `vm`. vCPU threads only. No series for a VM the sched program has not measured, and none for `_host` |
| `shukra_sched_vcpu_preempted_by_seconds_total` | counter, `vm`, `by`: `vm:<name>` for a thread of a QEMU process, otherwise a command name (`kworker`, `cilium-agent`) |
| `shukra_block_latency_seconds` | histogram, `vm`, `op` |
| `shukra_block_ops_total`, `shukra_block_bytes_total` | counter, `vm`, `op` |
| `shukra_block_latency_max_seconds` | gauge, `vm`, `op` |
| `shukra_tcp_connects_total`, `shukra_tcp_retransmits_total` | counter, `vm`. **The QEMU process's** sockets, not the guest's |
| `shukra_tap_bytes_total`, `shukra_tap_packets_total` | counter, `vm`, `tap`, `direction` (`from_guest`, `to_guest`) |
| `shukra_tap_dropped_packets_total` | counter, `vm`, `tap`. What **isolation** dropped |
| `shukra_tap_isolated` | gauge, `vm`, `tap`. 1 while isolated |
| `shukra_tap_connect_attempts_total`, `shukra_tap_connect_retransmits_total` | counter, `vm`, `tap`, `direction` (`out` is the guest's own, `in` is made to it) |
| `shukra_tap_connect_outcomes_total` | counter, `vm`, `tap`, `direction`, `result` (`accepted`, `refused`, `timed_out` or `ignored`, `blocked`) |
| `shukra_tap_handshake_seconds` | histogram, `vm`, `tap`. SYN to SYN-ACK of the guest's own connections |
| `shukra_tap_kernel_drops_total` | counter, `vm`, `tap`, `reason`. Only while the drops program is measuring. The Shukra/other split is on `/api/v1/trace/drops`, not here, because it is a difference of two counters read a moment apart and can dip |

Useful queries for the guest signals:

```promql
# refused outbound connections per second, per VM
sum by (vm) (rate(shukra_tap_connect_outcomes_total{direction="out",result="refused"}[5m]))

# the share of a VM's outbound connections that were never answered
sum by (vm) (rate(shukra_tap_connect_outcomes_total{direction="out",result="timed_out"}[5m]))
  / sum by (vm) (rate(shukra_tap_connect_attempts_total{direction="out"}[5m]))

# connections made to a VM, per second
sum by (vm) (rate(shukra_tap_connect_attempts_total{direction="in"}[5m]))

# how long a guest's connections take to be answered (p99)
histogram_quantile(0.99, sum by (le, vm) (rate(shukra_tap_handshake_seconds_bucket[5m])))

# packets the kernel dropped on a VM's tap, by reason
sum by (vm, reason) (rate(shukra_tap_kernel_drops_total[5m]))
```

## vCPU preemption

`sched_switch` fires when a thread leaves a CPU. If a QEMU thread leaves while it is still **runnable** (still on the run queue), it was taken off the CPU while it wanted to run: preempted. The program remembers when, and who took the CPU (the incoming thread and its command name), and when the thread next gets a CPU the wait is added to that thread's total and to the pair (this thread, that thread). A thread that goes to sleep is dequeued before the switch, so sleeping is never counted.

- **What the number is.** Time vCPU threads spent runnable but off a host CPU. It is the host's view of the guest losing its processor, and it is **not** the steal counter a guest reads: it does not include time the host was doing work for the guest, and the guest's own accounting is not consulted. Summed over a VM's vCPUs, so a 4-vCPU VM can be preempted for more than a second per second.
- **vCPU threads only.** An iothread that waited for a CPU is not the guest losing its processor, and a thread no VM owns is not counted at all. A thread is a vCPU by the role the daemon's scan gave it, so a thread that appeared since the last scan (every 2 seconds) is missed until the next.
- **Who.** A preemptor that is a thread of a QEMU process is named by its VM, `vm:<name>` (and `vm:<own name>` is the VM's own other threads: an iothread or another vCPU). Anything else is its command name with the per-CPU or per-instance suffix removed, so `kworker/3:1` and `kworker/u16:2` are one preemptor, `kworker`. The command name is what the kernel reported when the vCPU was preempted; a thread that renames itself after it starts is shown under its newest name. These are **host** process names.
- **A yield counts.** A thread that calls `sched_yield` while runnable is also off the CPU while it wants to run, and cannot be told apart from being preempted at this hook. KVM yields between vCPUs (paravirtual spinlocks, PLE), so some of the time attributed to `vm:<own name>` is that.
- **Totals are exact, the split is bounded.** The per-thread totals are exact. The table of who took the CPU is a fixed-size LRU keyed by the taking thread's id, which churns on a busy host, so the named preemptors of a very busy host can add up to a little less than the total.
- **Not a finding by itself.** A vCPU is preempted a little all the time. Explain reports `cpu_preempted` only from 200 ms in the window and 5% of the time the vCPUs wanted to run (20% is high confidence).
- **Cost.** Measured on a 12-CPU Xeon hypervisor with 10 VMs under the same live load: the previous `sched_switch` program took about 435 ns per switch, the new one about 490 ns with no VM watched and about 615 ns with the ten VMs watched, at about 60,000 switches a second. That is about 11 ms of CPU per second more, under 0.1% of the host. (These figures include the kernel's own run-time accounting, which was switched on for the measurement.)
- **Checked against the kernel** by a test that pins two CPU-bound threads to one CPU: the victim is charged about half the run and the taker is named by the command the test gave it. A sleeping thread on the same CPU is not charged, and removing the runnable check makes the test fail.
- **Across VMs.** When a preemptor is another VM (`vm:<name>`), `shukractl trace contention` joins it to that VM's own activity over the same window (its on-CPU time and KVM exits): a culprit that is busy is doing it to itself, and one that is nearly idle is being scheduled badly. Explain adds `noisy_neighbour` when one other VM accounts for at least half of a VM's preempted time (and the preemption is already a `cpu_preempted` finding). The pairs are also on `/metrics`: `shukra_sched_vcpu_preempted_by_seconds_total{vm="db",by="vm:web"}` is the time web took from db, so a dashboard needs no new series.
- **Where it is seen.** `shukractl trace sched`, `GET /api/v1/trace/sched` (`vcpuPreemptedNs`, `vcpuPreemptions`, `topPreemptors`), the Scheduler page, `shukra_sched_vcpu_preempted_*`, the threshold metric `vcpu_preempted_ms_per_sec`, and Explain.

## Right-sizing

`shukractl advise` and `GET /api/v1/advice` turn the counters into advice about a VM's size, over the last one to five minutes (five by default).

- **Halted** is the HLT exit time over what the vCPUs could have run for (the window times the number of vCPU threads). HLT exit handling lasts as long as the guest was idle, which is why halts are left out of the exit-latency histogram. It is a **lower bound** on idleness: a guest that idles by polling (`idle=poll`) never halts and reads as busy, and time the host spends halt-polling counts as CPU time.
- **A gap is shown, not hidden.** On the live hypervisor the three-vCPU VMs read exactly one third or two thirds halted, because their other vCPUs never execute HLT (offline in the guest, or idling with MWAIT or a polling loop). So `unaccountedFraction`, the share of capacity that is neither halted nor on a CPU, is reported, and `no_change` says when it is large (30% or more) that this is not proof the VM is right-sized. A halt is also counted when it ends, so a vCPU asleep in one very long halt looks less idle until it wakes.
- **Only where the CPU names the exit.** Exit reasons are named only on Intel hosts (AMD reuses small numbers for other things, arm64 reports an exception class). Elsewhere `idleAvailable` is `false`, the advisor says so (`idle_unavailable`) and claims nothing about over-provisioning. Starvation needs no halt time and is still reported.
- **Busy** is the vCPU threads' on-CPU time over the same capacity. The QEMU main thread, iothreads and vhost threads are not counted: they are not the guest's CPUs.
- **Thresholds** (constants in `internal/state/advice.go`): over-provisioned at 80% halted and 20% busy with two or more vCPUs, suggesting twice the headroom it used; starved at 50% busy and either 10% preempted or a 2 ms run-queue wait; nearly idle at 95% halted with one vCPU. A window under three minutes lowers the confidence.
- **Not an action.** Nothing here resizes a VM; a person decides.

## Known limits

- **Handshake outcomes.** A SYN is judged never answered after 3 seconds, counted when the counters are read (BPF has no timers), so a server that answers later is counted as never answered, not accepted. The table of pending SYNs has a fixed size: under a SYN flood the oldest are forgotten uncounted, though `attempts` still counts every SYN. A daemon restart forgets handshakes that were in flight. A repeat of the same SYN on a connection that has not been answered is a retransmit, and a SYN that reuses a four-tuple after the old one was forgotten is a new attempt.
- **Cost of `drops`.** It runs once for every packet the host drops anywhere, and returns after one map lookup unless the packet was on a VM tap. Measured on a 12-CPU Xeon hypervisor: 69 runs a second at about 255 ns each, which is 0.002% of one CPU. That is the per-call figure to scale by: a host dropping a million packets a second would spend about a quarter of a CPU here. (`bpftool prog show` reports `run_time_ns` and `run_cnt` for it while any process has run-time stats enabled.)
- The `drops` program reads `skb:kfree_skb` through the kernel's own BTF description of it, so it does not depend on where the fields are (Linux 6.9 moved them). It needs a drop reason to read, so Linux 5.17 or newer, and says why when it cannot run. A difference of fewer than 5 packets between the kernel's count and Shukra's is treated as skew between two reads, not as another program dropping traffic.
- Block bytes and requests are attributed to the task that **dispatched** the request, which is usually the submitting thread but not always: the block layer sometimes dispatches from a kernel worker, and those requests land on that worker's row, not the QEMU thread's. In an integration test on a 6.8 kernel about 3% of direct reads were attributed away from the thread that issued them. Treat a VM's block figures as slightly under-counted, most of all under heavy queueing. Latency percentiles are unaffected, since they come from the requests that were attributed.
- A connect to a v4-mapped address on an `IPV6_V6ONLY` socket is refused by the kernel before any connection is attempted, so it is not counted. A dual-stack socket's v4-mapped connect is counted once.
- Block requests are matched by device and sector between issue and completion. Two overlapping requests to the same sector can collide, and the older one is lost from the histogram.
- The `kvm` timing has run on a real Intel hypervisor (x86, Linux 6.8) with non-zero exit latency and named exit reasons. It has **not** been run on AMD or arm64 hardware, where the reasons are unnamed by design (below) and the timing is unproven.
- On arm64 the `kvm_pio` tracepoint does not exist (`kvm` attaches 3 of 4 hooks) and the exit reason field is an exception class.
