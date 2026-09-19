# API reference

`shukrad` serves JSON over HTTP on `-listen` (default `127.0.0.1:30970`). `shukractl`, the console and Prometheus all use this API and nothing else, so anything they show, you can fetch. The API only reads and, for two routes, isolates or releases a VM. It never loads BPF.

## Authentication

| Route | Key needed |
|---|---|
| `GET /healthz`, `GET /readyz` | none |
| every other `GET` | `Authorization: Bearer <key>`, the admin key or the read-only key |
| `POST /api/v1/isolate`, `POST /api/v1/release` | the admin key. The read-only key gets `403` |

- The admin key is `SHUKRA_API_KEY`. If it is unset the daemon uses the well-known dev key `shukra` and says so on stderr. `-no-auth` is the only way to serve without a key. An empty key never matches.
- `SHUKRA_READONLY_KEY` adds a key that can call every `GET`, `/metrics` and the event stream, and cannot isolate. Give that one to Prometheus and dashboards.
- Keys are compared in constant time. A key never appears in any response, in `/api/v1/doctor`, or in `systemctl show`.
- The API is plain HTTP unless the daemon runs with `-tls-cert` and `-tls-key`. On a non-loopback address the daemon warns at start, and `shukractl doctor` flags it.
- `X-Shukra-Actor: <name>` on a `POST` is recorded in the isolation audit trail. `shukractl` sends `shukractl`; a missing header is recorded as `api`.

## Conventions

- Times are RFC 3339 UTC. Durations in field names end in `Ns` (nanoseconds).
- **An empty list is `[]`, never `null`**, so a client can loop over any list without a special case.
- **A VM or program that is not being measured has no row and no series, not a zero.** `measured: false` says so where a response carries it. A name that matches nothing is an empty result, not a guess.
- Latency percentiles come from log2 histograms, so each is a bucket's high edge and can read up to 2x high. Histograms are 64 buckets: bucket *b* holds values from 2^*b* to 2^(*b*+1) nanoseconds.
- A response that reads a VM's counters says whose they are: `attribution: "qemu-process"` for the host side, `"guest-tap"` for what was seen on a VM's tap.

## Health

| Route | Returns |
|---|---|
| `GET /healthz` | `200 {"status":"ok"}` while the process is up |
| `GET /readyz` | `200` once the first scan has finished, `503` before. `{"ready", "programsAttached", "programsTotal"}` |

## Overview and inventory

| Route | Returns |
|---|---|
| `GET /api/v1/status` | `version`, `product`, `mode`, `datapath`, `healthy`, `vms`, `programsAttached`, `programsTotal`, `detections`, `summary`. The last line says whether guest tap attribution is attached |
| `GET /api/v1/vms` | `{"vms": [...]}`. Each VM: `name`, `uuid`, `runtime` (`libvirt`, `kubevirt` or `qemu`: a label from the command line), `pid`, `comm`, `taps`, `threadInfo` (each thread's `tid`, `comm` and inferred `role`: `vcpu`, `iothread`, `vhost`, `other`), `cmdline` |
| `GET /api/v1/programs` | `{"programs": [{"name","status","detail"}]}` for `kvm`, `sched`, `block`, `net`, `tap`, `drops`. `status` is `attached` or `detached`. `detail` says how many hooks, or why not |
| `GET /api/v1/doctor` | `{"worst", "checks": [{"id","status","title","detail","fix"}]}`. `status` is `ok`, `info`, `warn` or `fail`, worst first. Only reads; readable with the read-only key |
| `GET /api/v1/export` | One document: status, VMs, traces and events, for a bug report |

## Per-VM traces

All take `?vm=<name>` to narrow to one VM. Every response has a `rows` list.

| Route | What a row is |
|---|---|
| `GET /api/v1/trace/kvm` | Exit, entry, MMIO and PIO counts, exit-handling latency (`exitLatencyP50Ns`, `exitLatencyP99Ns`, `exitLatencyHist`), the costliest reasons by count and by time (Intel hosts name them). `measured` |
| `GET /api/v1/trace/sched` | On-CPU time, run-queue delay (`wakeupDelayP50Ns`, `wakeupDelayP99Ns`, `wakeupHist`). `?threads=1` adds a `threads` list, one row per QEMU thread with its role, so a slow vCPU can be told from a slow iothread |
| `GET /api/v1/trace/block` | Requests, bytes, slowest request and read/write latency histograms |
| `GET /api/v1/trace/net` | `tcp_v4_connect`/`tcp_v6_connect` counts and sampled retransmits **from the QEMU process**. Always `guestAttributed: false` |
| `GET /api/v1/trace/tap` | Per VM tap, from the guest's point of view: `fromGuestPackets/Bytes`, `toGuestPackets/Bytes`, `droppedPackets/Bytes` (isolation's), `isolated`, and what became of every TCP handshake (below) |
| `GET /api/v1/trace/drops` | What the kernel dropped on each VM tap. `measured`, then `taps` (per-tap totals) and `rows` (per reason). See [drops](drops.md) |

### Handshake fields on a tap row

`out*` is the guest's own connections and `in*` is connections made to the guest. Every outbound attempt is exactly one of accepted, refused, timed out or blocked, or is still waiting.

| Field | Meaning |
|---|---|
| `outSyn` | New connection attempts by the guest. A repeat of the same SYN is not one |
| `outAccepted` | Answered with a SYN-ACK |
| `outRefused` | Answered with an RST |
| `outTimedOut` | Never answered within 3 seconds |
| `outBlocked` | Dropped by isolation. Never pending, so never a timeout |
| `outRetransmits` | The same SYN sent again |
| `inSyn`, `inAccepted`, `inRefused`, `inIgnored`, `inBlocked`, `inRetransmits` | The same, for connections made to the guest. `inIgnored` is a SYN the guest never answered |
| `handshakeP50Ns`, `handshakeP99Ns`, `handshakeHist` | SYN to SYN-ACK time of the guest's own accepted connections |

### Drop fields

`GET /api/v1/trace/drops`: `taps` has, per tap, `kernelDrops` (all reasons), `shukraDropped` (isolation's own, counted from when the daemon started, like the kernel's numbers), `otherDrops` (what is left after subtracting Shukra's, and a full queue), `guestNotReading` (`FULL_RING`) and `reasons`. `rows` has one entry per reason with `count` and `location`, the kernel function that freed the packets.

## Explain and the recorder

| Route | Returns |
|---|---|
| `GET /api/v1/explain?vm=<name>&window=<dur>` | `vm`, `question`, ranked `findings` (`cause`, `confidence`, `summary`, `evidence`), `window`, `basis`, `evidence`, `missing`, `events`. `window` is `10s` to `5m`, or `0`/`lifetime`; the default is the last minute. Anything else is `400`. `missing` is part of the answer: what Shukra cannot see |
| `GET /api/v1/recorder?vm=<name>&window=<dur>` | The bounded per-VM flight recorder (default 60s window, cap 4096 events) |

Findings Shukra can give: `host_cpu_contention`, `storage_latency`, `kvm_exit_handling`, `tcp_retransmits`, `guest_traffic_dropped`, `guest_not_reading_nic`, `guest_connects_failing`, and `no_host_cause` (which says the cause may be inside the guest). `unknown_vm` and `not_measured` are returned alone.

## Events

An event carries `seq` (only grows), `product: "shukra"`, `kind`, `ts`, `vm` (`name`, `uuid`, `runtime`), `attribution`, `guest_attributed`, and the fields that kind uses.

| Kind | What it is | Attribution |
|---|---|---|
| `exec`, `exit` | A child of a QEMU process started or ended. `comm`, `ppid` | `qemu-process` |
| `tcp_connect`, `tcp_retransmit` | The QEMU process's own sockets | `qemu-process` |
| `block_slow`, `sched_delay` | A request or wakeup slower than the sample threshold. `latency_ns` | `qemu-process` |
| `guest_connect` | The guest sent a TCP SYN. `src` is the guest, `dst` and `dport` where to, `proto: "tcp"`, `iface`, `blocked` | `guest-tap` |
| `guest_flow` | The guest started a new UDP flow. `proto: "udp"` | `guest-tap` |
| `guest_inbound` | A TCP SYN was sent **to** the guest. `src` is the peer, `dst` the guest, `dport` the guest port | `guest-tap` |
| `guest_dns` | The guest asked for a name over UDP port 53. `dns_name` (lower-case), `qtype`, `src` the guest, `dst` the resolver, `dport: 53`, `blocked`, and `dns_truncated` when the name did not fit | `guest-tap` |
| `detection` | A rule fired. `rule`, `severity`, `message`, and the attribution of the event that triggered it | as the trigger |
| `vm_start`, `vm_stop` | A QEMU process appeared or went away | `qemu-process` |

`guest_attributed` is `true` only for an event seen on a VM's tap **and** naming a VM in the current scan. A tap no VM owns gives `unattributed`, never a guessed name.

| Route | Returns |
|---|---|
| `GET /api/v1/events?since=<seq>&vm=<name>` | `{"seq", "events"}`: events newer than `seq`, so a poller never misses one or repeats one. The daemon keeps the last 2048 |
| `GET /api/v1/stream?since=<seq>&vm=<name>` | The same as server-sent events. Each frame's `id` is the event `seq`, so a reconnect resumes with `Last-Event-ID` |
| `GET /api/v1/detections?vm=<name>` | Detections, capped like events |

## Security and isolation

| Route | Returns |
|---|---|
| `GET /api/v1/security?vm=<name>` | `detections`, `enforcement` (`tcx`, or `not_attached`), `allowList`, `durable` (whether isolation survives the daemon) and, when it cannot enforce, `reason` |
| `GET /api/v1/isolations` | The audit trail of isolate and release requests, and whether each took effect |
| `POST /api/v1/isolate` `{"vm": "<name>"}` | Drops the VM's tap traffic except ARP, IPv6 neighbour discovery and the management allow list. Returns `applied`, which is `true` only after the kernel took the change on every tap, `enforcement`, `taps`, `reason`. Refused without `-isolate-allow`, for an unknown VM, a VM with no tap, or a daemon without the tap program |
| `POST /api/v1/release` `{"vm": "<name>"}` | Lifts it |

## Metrics

`GET /metrics` is Prometheus text. A VM with no measured counters has no series. See [signals](signals.md) for the list, and the [tutorial](tutorials/08-lost-traffic.md) for queries.

## Errors

`400` for a bad parameter (with a message), `401` for a missing or wrong key, `403` for the read-only key on a `POST`, `503` from `/readyz` before the first scan. A VM name that matches nothing is `200` with an empty list.
