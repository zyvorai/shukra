# What each program measures

Everything here is the QEMU process, seen from the host. None of it is measured inside the guest. See [attribution](attribution.md).

| Program | Records | Caveat |
|---|---|---|
| `kvm` | Exit counts by reason. **Handling time**: `kvm_exit` to the next `kvm_entry` on the same vCPU thread, as a log2 histogram. Total time per reason | A halt blocks until an interrupt, so its time is guest idle. It is in the per-reason totals and left out of the latency histogram (reason 12 on VMX, 120 on SVM) |
| `sched` | On-CPU time. **Run-queue delay** (wakeup to running) as a log2 histogram, per task | Per QEMU thread with `?threads=1`, so a slow vCPU is distinguishable from a slow iothread |
| `block` | Completed requests, bytes, slowest request, and a log2 latency histogram, per direction | It is the QEMU I/O thread, not the guest filesystem. The slowest request is updated without a lock, so two CPUs racing can miss a slightly smaller maximum |
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
| `shukra_kvm_exit_handling_seconds_total` | counter, `vm`, `reason`, `name`. A halt's time is guest idle |

## Known limits

- Block bytes and requests are attributed to the task that **dispatched** the request, which is usually the submitting thread but not always: the block layer sometimes dispatches from a kernel worker, and those requests land on that worker's row, not the QEMU thread's. In an integration test on a 6.8 kernel about 3% of direct reads were attributed away from the thread that issued them. Treat a VM's block figures as slightly under-counted, most of all under heavy queueing. Latency percentiles are unaffected, since they come from the requests that were attributed.
- A connect to a v4-mapped address on an `IPV6_V6ONLY` socket is refused by the kernel before any connection is attempted, so it is not counted. A dual-stack socket's v4-mapped connect is counted once.

- Block requests are matched by device and sector between issue and completion. Two overlapping requests to the same sector can collide, and the older one is lost from the histogram.
- The `kvm` timing has been loaded by the kernel verifier and its hooks attach, but it has not run: the host it was developed against has no `/dev/kvm`. Read it as unproven until you have seen non-zero `exit_latency` on a real hypervisor.
- On arm64 the `kvm_pio` tracepoint does not exist (`kvm` attaches 3 of 4 hooks) and the exit reason field is an exception class.
