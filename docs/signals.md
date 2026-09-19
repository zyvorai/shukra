# What each program measures

Everything here is the QEMU process, seen from the host. None of it is measured inside the guest. See [attribution](attribution.md).

| Program | Records | Caveat |
|---|---|---|
| `kvm` | Exit counts by reason. **Handling time**: `kvm_exit` to the next `kvm_entry` on the same vCPU thread, as a log2 histogram. Total time per reason | A halt blocks until an interrupt, so its time is guest idle. It is in the per-reason totals and left out of the latency histogram (reason 12 on VMX, 120 on SVM) |
| `sched` | On-CPU time. **Run-queue delay** (wakeup to running) as a log2 histogram, per task | Per QEMU thread with `?threads=1`, so a slow vCPU is distinguishable from a slow iothread |
| `block` | Completed requests, bytes, slowest request, and a log2 latency histogram, per direction | It is the QEMU I/O thread, not the guest filesystem. The slowest request is updated without a lock, so two CPUs racing can miss a slightly smaller maximum |
| `tap` | Per-tap packets and bytes each way and what isolation dropped, from TCX on the VM tap. **What became of each TCP handshake**, both ways: accepted, refused, never answered, blocked by isolation, and retransmits, plus the time to be answered as a log2 histogram. A `guest_inbound` event per connection made to the guest. A `guest_connect` event per TCP SYN and a `guest_flow` event per new UDP flow, capped at 200 per tap per second | The only program that sees the guest. Needs Linux 6.6+. See [Guest traffic and isolation](tap.md) |
| `drops` | What the kernel dropped on each VM tap, counted by the kernel's own reason (`skb:kfree_skb`): TC_INGRESS, TC_EGRESS, FULL_RING and the rest, and the kernel function that freed the last one | Only the VM taps are counted. Shukra's own isolation drops appear as TC_INGRESS or TC_EGRESS, so they are subtracted using the tap program's `dropped` count: what is left is **someone else's**. A full queue (FULL_RING) is the guest not reading its NIC, and is reported on its own. The kernel function that freed them is named by the kernel itself (`bpf_snprintf` `%ps`, once when a reason is first seen on a tap), so it needs no capability; it is the function at the first free seen, and if the kernel cannot name it, `/proc/kallsyms` is tried and then the address is shown. Reason names come from this kernel's BTF, and an unknown reason is shown as its number |
| `net` | `tcp_v4_connect` and `tcp_v6_connect`, counted exactly in a kernel map. 1 in 64 retransmits become events, IPv4 and IPv6 | A dual-stack socket connecting to a v4-mapped address is counted once, by the IPv4 probe |

## Events

`exec` and `exit` are emitted only for a QEMU process and its children, not for every process on the host. `shukrad` tells the kernel which processes those are through a `watched` map, refreshed on each scan, so a child that starts in the first couple of seconds after a VM appears can be missed. Each event carries the parent's tgid from the kernel, which is how a short-lived child is still joined to its VM after it has gone. An unrelated parent stays unattributed.

Without that filter, 300 runs of `/bin/true` produced 330 exec and 328 exit events on a test host. That is enough to push connects and detections out of the 2048-event list within seconds on a busy hypervisor.

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

| Series | Type |
|---|---|
| `shukra_block_latency_seconds` | histogram, `vm`, `op` |
| `shukra_block_ops_total`, `shukra_block_bytes_total` | counter, `vm`, `op` |
| `shukra_block_latency_max_seconds` | gauge, `vm`, `op` |
| `shukra_sched_runqueue_delay_seconds` | histogram, `vm` |
| `shukra_kvm_exit_latency_seconds` | histogram, `vm` |
| `shukra_kvm_exits_by_reason_total` | counter, `vm`, `reason`, `name` (Intel only) |
| `shukra_tap_kernel_drops_total` | counter, `vm`, `tap`, `reason`. Only while the drops program is measuring. The Shukra/other split is on `/api/v1/trace/drops`, not here, because it is a difference of two counters read a moment apart and can dip |
| `shukra_tap_connect_attempts_total`, `shukra_tap_connect_retransmits_total` | counter, `vm`, `tap`, `direction` (`out` is the guest's own, `in` is made to it) |
| `shukra_tap_connect_outcomes_total` | counter, `vm`, `tap`, `direction`, `result` (`accepted`, `refused`, `timed_out` or `ignored`, `blocked`) |
| `shukra_tap_handshake_seconds` | histogram, `vm`, `tap`. SYN to SYN-ACK of the guest's own connections |
| `shukra_kvm_exit_handling_seconds_total` | counter, `vm`, `reason`, `name`. A halt's time is guest idle |

## Known limits

- **Cost of `drops`.** It runs once for every packet the host drops anywhere, and returns after one map lookup unless the packet was on a VM tap. Measured on a 12-CPU Xeon hypervisor: 69 runs a second at about 255 ns each, which is 0.002% of one CPU. That is the per-call figure to scale by: a host dropping a million packets a second would spend about a quarter of a CPU here. (`bpftool prog show` reports `run_time_ns` and `run_cnt` for it while any process has run-time stats enabled.)
- The `drops` program reads `skb:kfree_skb` through the kernel's own BTF description of it, so it does not depend on where the fields are (Linux 6.9 moved them). It needs a drop reason to read, so Linux 5.17 or newer, and says why when it cannot run. A difference of fewer than 5 packets between the kernel's count and Shukra's is treated as skew between two reads, not as another program dropping traffic.
- Block bytes and requests are attributed to the task that **dispatched** the request, which is usually the submitting thread but not always: the block layer sometimes dispatches from a kernel worker, and those requests land on that worker's row, not the QEMU thread's. In an integration test on a 6.8 kernel about 3% of direct reads were attributed away from the thread that issued them. Treat a VM's block figures as slightly under-counted, most of all under heavy queueing. Latency percentiles are unaffected, since they come from the requests that were attributed.
- A connect to a v4-mapped address on an `IPV6_V6ONLY` socket is refused by the kernel before any connection is attempted, so it is not counted. A dual-stack socket's v4-mapped connect is counted once.

- Block requests are matched by device and sector between issue and completion. Two overlapping requests to the same sector can collide, and the older one is lost from the histogram.
- The `kvm` timing has been loaded by the kernel verifier and its hooks attach, but it has not run: the host it was developed against has no `/dev/kvm`. Read it as unproven until you have seen non-zero `exit_latency` on a real hypervisor.
- On arm64 the `kvm_pio` tracepoint does not exist (`kvm` attaches 3 of 4 hooks) and the exit reason field is an exception class.
