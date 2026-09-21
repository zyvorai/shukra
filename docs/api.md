# API reference

`shukrad` serves JSON over HTTP on `-listen` (default `127.0.0.1:30970`). `shukractl`, the console and Prometheus use this API and nothing else, so anything they show, you can fetch. The API reads state the daemon already holds. It never loads BPF and never touches a VM, with one kind of exception: the routes marked **admin** below change something (isolate a VM, decide a proposal, forget a baseline, put a VM under an egress policy), and each records who asked.

Contents: [Conventions](#conventions) · [Route index](#route-index) · [Health](#health) · [Overview and inventory](#overview-and-inventory) · [Per-VM traces](#per-vm-traces) · [Explain, incident, advice and the recorder](#explain-incident-advice-and-the-recorder) · [Events and the stream](#events-and-the-stream) · [Security and isolation](#security-and-isolation) · [Learned baselines](#learned-baselines) · [Egress policy](#egress-policy) · [Responses](#responses) · [Metrics](#metrics) · [Errors](#errors)

The examples below were produced by running the daemon's own handlers over a fixture of two VMs, except `advice`, whose fixture had too little history to advise: that example uses the numbers a longer run would give, in the shape the code writes. Host names, VM names and addresses are made up, arrays of histogram counts are shortened to `[...]` (each is 64 numbers), and `...` stands for content trimmed for length, such as an object shown elsewhere on the page.

```bash
export SHUKRA_URL=http://127.0.0.1:30970
export SHUKRA_API_KEY=...            # the admin key, or the read-only key for a GET
curl -s -H "Authorization: Bearer $SHUKRA_API_KEY" "$SHUKRA_URL/api/v1/status"
```

## Conventions

### Authentication

| Route | Key needed |
|---|---|
| `GET /healthz`, `GET /readyz`, and the console's own files (`/`, `/assets/...`, when `-web` points at a build) | none |
| every other `GET`, including `/metrics` and `/api/v1/stream` | `Authorization: Bearer <key>`: the admin key or the read-only key |
| every `POST` | the admin key. The read-only key gets `403` |

- The admin key is `SHUKRA_API_KEY`. If it is unset the daemon uses the well-known dev key `shukra` and warns on stderr. `-no-auth` is the only way to serve without a key, and then nothing is checked at all, `POST` included. An empty key never matches.
- `SHUKRA_READONLY_KEY` adds a second key that can call every `GET`, `/metrics` and the event stream, and cannot change anything. Give that one to Prometheus and dashboards. It must differ from the admin key: the daemon refuses to start if the two are equal.
- Keys are compared in constant time, and both are always compared so the time taken does not say which one matched. A key never appears in any response, in `/api/v1/doctor`, or in `systemctl show`.
- The API is plain HTTP unless the daemon runs with `-tls-cert` and `-tls-key` (`SIGHUP` reloads the certificate). On a non-loopback address the daemon warns at start, and [`shukractl doctor`](doctor.md) flags it.
- `X-Shukra-Actor: <name>` on a `POST` is an optional client label. It is not authentication. The record names the key that matched (`admin:` or `readonly:` plus six hex characters of SHA-256 of the key), the label, the source address, a request id (`X-Request-Id`, or one the daemon generates), the role and the operation. `shukractl` sends `shukractl`. A missing or rejected label is omitted. The response carries `X-Request-Id`.
- Every response sets `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and a content security policy (`style-src` allows `'unsafe-inline'` for the console). `Strict-Transport-Security` (`max-age=31536000; includeSubDomains`) is set only when the connection to the daemon is TLS.
- Request bodies are read up to 64 KiB, or 1 MiB for the policy routes.

### Data

- Times are RFC 3339. Durations in field names end in `Ns` (nanoseconds). A time that was never set (`expires` on an action that does not lapse, `decided` on one nobody has decided) reads `0001-01-01T00:00:00Z`, not absent.
- **Lists are `[]`, never `null`.** Every route that carries a list of rows says `[]` when there are none, including `detections`, `isolations`, the `threads` of `trace/sched?threads=1`, the `security` board's `detections` and `allowList`, and every list in `export`. A test asks each GET route with nothing known and fails on a `null`. (A daemon older than this rule answered `null` for those; treat `null` as empty if you must talk to one.)
- **A program that is not measuring does not invent a zero.** In `/metrics` a VM that is not measured has no series. In `trace/kvm`, `trace/sched` and `trace/block` a known VM whose counters are all zero still has a row, and `measured: false` says so. `trace/memory` has a row only when that VM has reclaimed or been OOM-killed. `trace/net` and `trace/tap` rows have no `measured` field, `trace/drops` says `measured` once for the whole response, and `trace/contention` has no row for a VM the sched program has not measured. A VM name that matches nothing is an empty result, not an error and not a guess.
- A row named `_host` is everything the program counted that belongs to no VM's threads. It has no vCPUs, so it has no preemption.
- Latency percentiles come from log2 histograms, so each is a bucket's high edge and can read up to 2x high. A histogram array has 64 buckets: bucket *b* counts values from 2^*b* up to 2^(*b*+1) nanoseconds, and bucket 0 also holds zero.
- A response that reads a VM's counters says whose they are: `attribution: "qemu-process"` for the host side (what the VMM process did), `"guest-tap"` for what was seen on a VM's tap, `"unattributed"` when there is no VM to name.
- `?vm=<name>` narrows a response to one VM wherever it is accepted. An unknown query parameter is ignored.

### Windows

| Where | Accepted | Default | Otherwise |
|---|---|---|---|
| `explain`, `trace/contention`, live | `10s` to `5m`, or `0` / `lifetime` | `60s` | `400` |
| `advice` | `1m` to `5m` | `5m` | `400` |
| `explain?at=`, `incident` | `5m` to `6h` | `15m` | `400` |
| `recorder` | any positive Go duration | `60s` | a bad or non-positive value is ignored, and the default is used |

`at` is an RFC 3339 time, or a negative age such as `-90m`. A time more than a minute in the future is `400`. When there is too little history for the window, a live answer falls back to `lifetime` and says so in its `window` field.

## Route index

| Method and path | Key | What it is |
|---|---|---|
| `GET /healthz` | none | The process is up |
| `GET /readyz` | none | The first scan has finished |
| `GET /metrics` | read | Prometheus text. [Metrics](#metrics) |
| `GET /api/v1/status` | read | Version, mode, counts |
| `GET /api/v1/vms` | read | VMs found on the host |
| `GET /api/v1/programs` | read | The seven observation programs and whether each is attached |
| `GET /api/v1/doctor` | read | The daemon's self-audit. [Doctor](doctor.md) |
| `GET /api/v1/export` | read | One document for a bug report |
| `GET /api/v1/trace/kvm` `sched` `block` `memory` `net` `tap` `drops` | read | Per-VM counters |
| `GET /api/v1/trace/contention` | read | Who took whose vCPU time |
| `GET /api/v1/explain` | read | Why a VM looks slow, now or at a past time |
| `GET /api/v1/incident` | read | Everything about a VM around a moment, in one document |
| `GET /api/v1/advice` | read | Is each VM the right size |
| `GET /api/v1/recorder` | read | The per-VM flight recorder |
| `GET /api/v1/events` | read | Discrete events since a sequence number |
| `GET /api/v1/stream` | read | The same as server-sent events |
| `GET /api/v1/detections` | read | Detections held in memory |
| `GET /api/v1/security` | read | Detections and the state of isolation |
| `GET /api/v1/isolations` | read | The isolate and release audit trail |
| `POST /api/v1/isolate`, `POST /api/v1/release` | **admin** | Isolate a VM's taps, or lift it |
| `GET /api/v1/baseline` | read | What each VM has learned as normal |
| `POST /api/v1/baseline/forget` | **admin** | Start one VM's learning over |
| `GET /api/v1/policy` | read | Egress policies |
| `GET /api/v1/policy/proposal` | read | The policy a VM's baseline suggests |
| `POST /api/v1/policy/apply` `confirm` `remove` | **admin** | Change an egress policy |
| `GET /api/v1/actions` | read | What responses decided |
| `POST /api/v1/actions/<id>/approve`, `.../reject` | **admin** | Decide a proposal |
| `GET /api/v1/actions/<id>/incident` | read | The incident bundle an action was made on |

A path that matches no route is `404`. A method the route does not take is `405` with an `Allow` header.

## Health

| Route | Returns |
|---|---|
| `GET /healthz` | `200 {"status": "ok"}` while the process is up |
| `GET /readyz` | `200` once the first scan has finished, `503` before |

```json
{
  "ready": true,
  "programsAttached": 7,
  "programsTotal": 7
}
```

Neither needs a key, so a load balancer or a systemd watchdog can use them. Neither says the programs are attached: `ready` means the daemon has scanned once, and a host with no BPF is ready with `programsAttached: 0`.

## Overview and inventory

### `GET /api/v1/status`

```json
{
  "version": "0.1.0",
  "product": "shukra",
  "tagline": "eBPF-powered runtime intelligence and security for KVM",
  "mode": "observe",
  "datapath": "tracepoint-kprobe",
  "healthy": true,
  "vms": 2,
  "programsAttached": 7,
  "programsTotal": 7,
  "detections": 1,
  "summary": "observe: host traces, and guest traffic on the VM taps (2 taps via tcx, enforcement survives a daemon restart)"
}
```

`summary` says whether guest tap attribution is attached. `detections` is how many are held in memory (at most 2048).

### `GET /api/v1/vms`

```json
{
  "vms": [
    {
      "name": "payment-prod-03",
      "uuid": "5c1d9f0e-7a4b-4c1e-9b1a-2f6d3e8a4c10",
      "runtime": "libvirt",
      "hypervisor": "hv-01",
      "pid": 4121,
      "comm": "qemu-system-x86",
      "taps": ["vnet4"],
      "threads": [4121, 4130, 4131, 4140],
      "threadInfo": [
        { "tid": 4121, "comm": "qemu-system-x86", "role": "other" },
        { "tid": 4130, "comm": "CPU 0/KVM", "role": "vcpu" },
        { "tid": 4131, "comm": "CPU 1/KVM", "role": "vcpu" },
        { "tid": 4140, "comm": "IO iothread1", "role": "iothread" }
      ],
      "cmdline": "/usr/bin/qemu-system-x86_64 -name guest=payment-prod-03,debug-threads=on -uuid 5c1d9f0e-..."
    }
  ]
}
```

- `runtime` is `qemu`, `libvirt`, `kubevirt` or `fluxvm`. The first three are read from the QEMU command line: `libvirt` and `kubevirt` are labels, not a query of either system. `fluxvm` means the name, UUID and `taps` came from FluxVM's `vms.json`; `taps` is then the host interface, `vh<8hex>` for the default per-VM netns. See [FluxVM](tap.md#fluxvm).
- `hypervisor` is the host name of the machine `shukrad` runs on.
- `threadInfo[].role` is inferred from the thread's name: `vcpu`, `iothread`, `vhost` or `other`. A `trace/sched?threads=1` row says `unknown` where no role was read.
- `taps` is empty for a VM on user-mode networking, which has no host interface. `threads`, `threadInfo`, `comm`, `uuid`, `hypervisor` and `cmdline` are left out when unknown.
- `name` is `qemu-unnamed` for a QEMU process started without `-name`.

### `GET /api/v1/programs`

```json
{
  "programs": [
    { "name": "kvm", "status": "attached", "detail": "4 hooks" },
    { "name": "sched", "status": "attached", "detail": "4 hooks" },
    { "name": "block", "status": "attached", "detail": "3 hooks" },
    { "name": "mem", "status": "attached", "detail": "3 hooks" },
    { "name": "net", "status": "attached", "detail": "3 hooks" },
    { "name": "vmm", "status": "attached", "detail": "15 hooks" },
    { "name": "drops", "status": "attached", "detail": "1 hooks" },
    { "name": "tap", "status": "attached", "detail": "2 taps via tcx, enforcement survives a daemon restart" }
  ]
}
```

There are eight programs. `status` is `attached`, `detached` or `missing` (the object is not in this binary). `detail` says how many hooks, or why not: `3/4 hooks; <error>` is a program that attached part of what it wanted, and a build without BPF says `CO-RE objects are not linked in this binary` on every line. `tap` is attached per VM interface, so it is `detached` with `no VM tap interfaces to attach to yet` until a VM with a tap exists. `vmm` says `turned off with -vmm-tripwires=false` when it was switched off. What each one records: [signals](signals.md#what-each-program-measures).

### `GET /api/v1/doctor`

```json
{
  "worst": "warn",
  "checks": [
    {
      "id": "persistence",
      "status": "warn",
      "title": "Nothing is kept across a restart",
      "detail": "Detections, isolation records and the flight recorder are lost, and recorded isolations cannot be re-applied.",
      "fix": "Start with -data-dir /var/lib/shukra (the shipped unit does)."
    },
    { "id": "auth", "status": "ok", "title": "The API key is not the dev key" }
  ]
}
```

`status` is `ok`, `info`, `warn` or `fail`, worst first. `worst` is the worst status present. `detail` and `fix` are left out when empty. It only reads state, and the read-only key is enough. Every check id, when it fires and what to do is in [doctor](doctor.md).

### `GET /api/v1/export`

One document for a bug report: `status`, `vms`, `programs`, `kvm`, `sched`, `block`, `net` (the same rows as the trace routes, all VMs) and `events` (everything the event list holds). It has no `tap` or `drops` rows. It contains VM names, addresses and DNS names, so treat it like the event list.

## Per-VM traces

Every route takes `?vm=<name>` and answers `{"rows": [...]}` with one row per VM, plus a `_host` row where the program counted something that is not a VM's.

### `GET /api/v1/trace/kvm`

```json
{
  "rows": [
    {
      "vm": "payment-prod-03",
      "runtime": "libvirt",
      "exits": 943000,
      "entries": 943000,
      "mmio": 31000,
      "pio": 12000,
      "topReasons": [
        { "reason": 12, "count": 900000, "totalNs": 41000000000, "name": "hlt" },
        { "reason": 48, "count": 31000, "totalNs": 2100000000, "name": "ept_violation" },
        { "reason": 30, "count": 12000, "totalNs": 900000000, "name": "io_instruction" }
      ],
      "topReasonsByTime": [...],
      "exitLatencyP50Ns": 4096,
      "exitLatencyP99Ns": 8192,
      "exitLatencyHist": [...],
      "measured": true
    }
  ]
}
```

`topReasons` are the three most frequent exit reasons, `topReasonsByTime` (same shape) the three that cost the most host time. `name` is set only on Intel hosts; AMD and arm64 rows carry the number alone, and a name is never guessed. A halt (`hlt`) blocks until an interrupt, so its `totalNs` is guest idle time and it is left out of `exitLatencyP50Ns`, `exitLatencyP99Ns` and `exitLatencyHist`, which measure `kvm_exit` to the next `kvm_entry`.

### `GET /api/v1/trace/sched`

```json
{
  "rows": [
    {
      "vm": "payment-prod-03",
      "onCpuNs": 112000000000,
      "wakeupDelayNs": 3800000000,
      "wakeupCount": 260000,
      "wakeupDelayP50Ns": 32768,
      "wakeupDelayP99Ns": 131072,
      "wakeupHist": [...],
      "vcpuPreemptedNs": 3500000000,
      "vcpuPreemptions": 1800,
      "topPreemptors": [
        { "who": "vm:batch-07", "ns": 3000000000 },
        { "who": "kworker/3:1", "ns": 500000000 }
      ],
      "measured": true
    }
  ],
  "threads": [
    { "vm": "payment-prod-03", "tid": 4130, "comm": "CPU 0/KVM", "role": "vcpu",
      "onCpuNs": 92000000000, "wakeupDelayNs": 3400000000, "wakeupCount": 210000,
      "wakeupDelayP99Ns": 131072, "preemptedNs": 3500000000 }
  ]
}
```

- On-CPU time and run-queue delay (wakeup to running) are for the whole VMM thread group.
- `vcpuPreemptedNs` and `vcpuPreemptions` are time the VM's vCPU threads were runnable but off a host CPU, and how many times. `topPreemptors` says who had the CPU: `vm:<name>` for a thread of a QEMU process (possibly the same VM) or a host command name. Most time first, at most five, `[]` when none. This is the host's view of losing the CPU, not the guest's steal counter.
- `?threads=1` adds `threads`: one row per VMM thread that has counters, with its role, so a slow vCPU can be told from a slow iothread. `preemptedNs` is present on a vCPU that was preempted.

### `GET /api/v1/trace/contention`

`?vm=<victim>&window=<dur>`. Who took whose vCPU time, and what the taker was doing meanwhile, over one window.

```json
{
  "note": "Who took each VM's vCPU time: other VMs (pairs), the VM's own other threads, and host tasks. ...",
  "window": "lifetime",
  "pairs": [
    { "victim": "payment-prod-03", "culprit": "batch-07", "preemptedNs": 3000000000, "share": 0.857 }
  ],
  "victims": [
    {
      "vm": "payment-prod-03",
      "preemptedNs": 3500000000,
      "preemptions": 1800,
      "byOtherVmsNs": 3000000000,
      "bySelfNs": 0,
      "byHostNs": 500000000,
      "topHostTasks": [ { "who": "kworker/3:1", "ns": 500000000 } ]
    }
  ],
  "culprits": [
    { "vm": "batch-07", "tookNs": 3000000000, "victims": 1, "onCpuNs": 380000000000, "exits": 1000 }
  ]
}
```

- `pairs`: one VM's CPU taken by one other VM. `share` is that pair's part of everything that preempted the victim's vCPUs, 0 to 1. Most time first.
- `victims`: every measured VM (or only `vm`), split into what other VMs took (`byOtherVmsNs`), what its own other threads took (`bySelfNs`) and what host tasks took (`byHostNs`, with the five biggest in `topHostTasks`). A VM nothing preempted has a row of zeros, which is a measurement.
- `culprits`: each VM that took CPU from others, how many VMs it did it to, and its own `onCpuNs` and `exits` over the same window: a busy culprit is doing it to itself, a nearly idle one is being scheduled badly.
- `window` is what it really covered (`1m0s`) or `lifetime` when there was too little history. A VM the sched program has not measured has no row. The lists are `[]`, never `null`.

### `GET /api/v1/trace/block`

```json
{
  "rows": [
    {
      "vm": "payment-prod-03",
      "issues": 88000,
      "readP50Ns": 262144, "readP99Ns": 524288,
      "writeP50Ns": 524288, "writeP99Ns": 1048576,
      "readMaxNs": 41000000, "writeMaxNs": 9000000,
      "readOps": 61000, "writeOps": 27000,
      "readBytes": 2500000000, "writeBytes": 1100000000,
      "readHist": [...], "writeHist": [...],
      "queueReadP50Ns": 65536, "queueReadP99Ns": 262144,
      "queueWriteP50Ns": 131072, "queueWriteP99Ns": 524288,
      "readErrors": 0, "writeErrors": 2,
      "measured": true
    }
  ]
}
```

These are the QEMU I/O thread's requests, not the guest filesystem. `readP50Ns` and `readP99Ns` are service time, from issue to completion. `queueReadP50Ns` and `queueReadP99Ns` are how long the request sat in the host queue before the device took it. `readErrors` and `writeErrors` are completions with a non-zero status. `readMaxNs` and `writeMaxNs` are the slowest request since the daemon attached; they are updated without a lock, so two CPUs racing can miss a slightly smaller maximum.

### `GET /api/v1/trace/memory`

```json
{
  "note": "Direct reclaim and OOM kills of the VMM process, not the guest's own memory.",
  "rows": [
    {
      "vm": "payment-prod-03",
      "reclaimCount": 4,
      "reclaimNs": 80000000,
      "reclaimP99Ns": 33554432,
      "oomKills": 0,
      "measured": true
    }
  ]
}
```

A VM that has not reclaimed and has not been OOM-killed is absent, not a zero row. `oom_kill` and `reclaim_stall` events (a stall of 10 ms or more) are on the event stream. This is the host process, not the guest's own memory.

### `GET /api/v1/trace/net`

```json
{
  "attribution": "qemu-process",
  "guestAttributed": false,
  "note": "These are connects from the QEMU process, not the guest.",
  "rows": [
    { "vm": "payment-prod-03", "connects": 3, "retransmits": 1, "attribution": "qemu-process",
      "guest_attributed": false, "note": "Connects and retransmits from the QEMU process, not the guest. ..." }
  ]
}
```

`tcp_v4_connect` and `tcp_v6_connect` counts (exact) and retransmits (1 in 64 is sampled into events) **from the VMM process**: migration, a remote disk, a monitor socket. Never guest traffic; for that use `trace/tap`. Every row has `guest_attributed: false`.

### `GET /api/v1/trace/tap`

From the guest's point of view, per interface. The interface is the tap, or FluxVM's host veth.

```json
{
  "attribution": "guest-tap",
  "guestAttributed": true,
  "note": "Traffic seen on the host side of each VM tap: from_guest is what the guest sent, to_guest is what was sent to it.",
  "rows": [
    {
      "vm": "payment-prod-03",
      "tap": "vnet4",
      "fromGuestPackets": 812345, "fromGuestBytes": 610000000,
      "toGuestPackets": 790001, "toGuestBytes": 1900000000,
      "droppedPackets": 0, "droppedBytes": 0,
      "isolated": false,
      "outSyn": 50, "outAccepted": 40, "outRefused": 6, "outTimedOut": 3, "outRetransmits": 4, "outBlocked": 1,
      "inSyn": 9, "inAccepted": 2, "inRefused": 3, "inIgnored": 4, "inRetransmits": 1, "inBlocked": 0,
      "handshakeP50Ns": 262144, "handshakeP99Ns": 524288, "handshakeHist": [...]
    }
  ]
}
```

`droppedPackets` and `droppedBytes` are what Shukra dropped, by isolation or by an enforcing egress policy, and `isolated` says isolation is on. `out*` is the guest's own connections and `in*` is connections made to the guest. Every outbound attempt is exactly one of accepted, refused, timed out or blocked, or is still waiting.

| Field | Meaning |
|---|---|
| `outSyn` | New connection attempts by the guest. A repeat of the same SYN is not one |
| `outAccepted` | Answered with a SYN-ACK |
| `outRefused` | Answered with an RST |
| `outTimedOut` | Never answered within 3 seconds |
| `outBlocked` | Dropped by Shukra (isolation or an egress policy). Never pending, so never a timeout |
| `outRetransmits` | The same SYN sent again |
| `inSyn`, `inAccepted`, `inRefused`, `inIgnored`, `inBlocked`, `inRetransmits` | The same, for connections made to the guest. `inIgnored` is a SYN the guest never answered |
| `handshakeP50Ns`, `handshakeP99Ns`, `handshakeHist` | SYN to SYN-ACK time of the guest's own accepted connections (`[]` until one is seen) |

### `GET /api/v1/trace/drops`

What the kernel dropped on each VM tap, by the kernel's own reason. See [drops](drops.md).

```json
{
  "attribution": "guest-tap",
  "guestAttributed": true,
  "measured": true,
  "note": "Packets the kernel dropped on each VM tap, by the kernel's own reason. ...",
  "taps": [
    {
      "vm": "payment-prod-03", "tap": "vnet4",
      "kernelDrops": 21, "shukraDropped": 0, "otherDrops": 9, "guestNotReading": 12,
      "reasons": [ { "reason": "FULL_RING", "count": 12 }, { "reason": "OTHERHOST", "count": 9 } ]
    }
  ],
  "rows": [
    { "vm": "payment-prod-03", "tap": "vnet4", "reason": "FULL_RING", "count": 12, "location": "tun_net_xmit" }
  ]
}
```

- `measured: false` means the drops program is not attached; `taps` and `rows` are then `[]`, which says nothing about drops.
- `taps`, per tap: `kernelDrops` (all reasons), `shukraDropped` (isolation's and egress policy's own, counted from when the daemon started, like the kernel's numbers), `guestNotReading` (`FULL_RING`: the tap's queue was full) and `otherDrops`, which is what is left after subtracting both. `otherDrops` is someone else's.
- `rows`, per tap and reason: `count`, and `location`, the kernel function that freed the packets.
- Only taps a VM owns appear.

## Explain, incident, advice and the recorder

### `GET /api/v1/explain`

`?vm=<name>&window=<dur>` for the last minute (or up to five), `?vm=<name>&at=<time>&window=<dur>` for a past time. See [Windows](#windows).

```json
{
  "vm": { "name": "payment-prod-03", "runtime": "libvirt", "pid": 4121, ... },
  "question": "why is this VM slow?",
  "findings": [
    {
      "cause": "guest_not_reading_nic",
      "confidence": "medium",
      "summary": "The tap's queue is full, so the host cannot hand this VM the packets it is sent. The guest is not taking them: it is stalled, has no working NIC driver, or is overloaded.",
      "evidence": ["12 packets were dropped on tap vnet4 because its queue was full."]
    }
  ],
  "window": "lifetime",
  "basis": "Latencies are since the daemon attached, from log2 buckets, so each can read up to 2x high. They are the QEMU process's, not the guest's.",
  "evidence": [
    "Identity comes from the QEMU command line, not from inside the guest.",
    "KVM exit counters are present for this thread group."
  ],
  "missing": [
    "CPU steal as the guest counts it (Shukra measures the host's view: how long the vCPUs were preempted)",
    "in-guest process identity"
  ],
  "events": [ ... ]
}
```

- `vm` is the VM as `/api/v1/vms` gives it, and `events` are the recorder's events for it: the last 60 seconds, or with `at` up to the ten minutes before it.
- `findings` are ranked host-side causes, best supported first. `confidence` is `high`, `medium` or `low`. Each has `cause`, `summary` and `evidence`.
- `window` is what the verdict really weighed: `1m2s`, or `lifetime` when there was not enough history yet or `window=0` was asked for. `basis` says the same in words.
- `missing` is part of the answer: what Shukra cannot see. It says `guest tap attribution` is missing while the tap program is not attached.
- With `at`, the verdict is for a past time, built from the stored snapshots (every 5 minutes, under `-data-dir`) between `at - window` and `at`. The answer adds `at` and `resolution` (`5m0s snapshots: the verdict stands on <time> and <time>`), and the `question` reads "why was this VM slow?". If nothing is stored for that time the one finding is `no_history` and its `summary` says why: no `-data-dir`, no snapshot at or before that time, the nearest one is more than ten minutes old (the daemon was probably not running), or not enough history before it. A VM that was not running then is `unknown_vm`.

Causes Shukra can give:

| `cause` | Says |
|---|---|
| `host_cpu_contention` | The VM's threads wait for a host CPU after being woken (run-queue delay) |
| `cpu_preempted` | The host took CPU away from the vCPUs. The evidence says how much and who took it |
| `noisy_neighbour` | Most of what was taken went to one other VM, which the finding names. Follows `cpu_preempted` |
| `storage_latency` | Block requests from QEMU are slow (p99 of at least 10 ms) |
| `kvm_exit_handling` | The host is slow to service KVM exits |
| `tcp_retransmits` | The QEMU process is retransmitting: host traffic such as migration or a remote disk |
| `guest_traffic_dropped` | The kernel is dropping the VM's packets on its tap and Shukra's own isolation is not the cause |
| `guest_not_reading_nic` | The tap's queue is full: the guest is not taking what it is sent |
| `guest_connects_failing` | Most of the guest's outbound connections were refused or never answered |
| `no_host_cause` | Nothing host-side stands out, so the cause may be inside the guest |
| `unknown_vm`, `not_measured` | Returned alone: no such VM in the scan, or no kernel program has measured it |
| `no_history` | Returned alone, with `at`: nothing is stored for that time |

### `GET /api/v1/incident`

`?vm=<name>&at=<time>&window=<dur>`. `vm` is required (`400 vm is required`). One document about a VM around a moment, for a ticket.

```json
{
  "product": "shukra",
  "generatedAt": "2026-09-20T14:58:31Z",
  "vm": "payment-prod-03",
  "at": "now",
  "window": "15m0s",
  "explain": { ... },
  "detections": [ ... ],
  "events": [ ... ],
  "isolations": [ ... ],
  "enforcement": "tcx",
  "allowList": ["10.0.0.0/24"],
  "programs": [ ... ],
  "note": "Contains VM names, addresses and DNS names. Treat it like the event list."
}
```

`explain` is as `/api/v1/explain` gives it, live or for `at`. `detections` are the VM's detections in the window, `events` the recorder's events in the window (at most 500, the newest), `isolations` the VM's isolate and release requests in the window, `programs` as `/api/v1/programs`. `at` is `now`, or the moment asked for. A live bundle's `explain` looks back at most five minutes; the rest of the window is for the detections, events and isolations. Every list is `[]`, never `null`. It holds VM names, addresses and DNS names and nothing from the daemon's configuration except the isolate allow list.

### `GET /api/v1/advice`

`?vm=<name>&window=<dur>`. Is each VM the right size. It advises a person and changes nothing.

```json
{
  "note": "Advice for a person, never an action. Idleness is halt time, a lower bound ...",
  "window": "4m58s",
  "rows": [
    {
      "vm": "batch-07",
      "vcpus": 2,
      "window": "4m58s",
      "idleAvailable": true,
      "idleFraction": 0.91,
      "busyFraction": 0.07,
      "busyVcpus": 0.14,
      "preemptShare": 0.0,
      "unaccountedFraction": 0.02,
      "runqueueDelayP99Ns": 8192,
      "advice": [
        {
          "kind": "overprovisioned",
          "confidence": "medium",
          "summary": "This VM has 2 vCPUs and used about 0.1 of them. 1 would leave it twice the headroom it used. ...",
          "evidence": ["Over 4m58s its vCPUs were halted 91% of the time they could have run and on a CPU 7%. ..."]
        }
      ]
    }
  ]
}
```

- `vcpus` counts the VM's vCPU threads. `window` on a row is what it really covered, or `none` when there was not enough.
- `idleAvailable` says halt time is named on this CPU (Intel hosts). `idleFraction` is halt time over what the vCPUs could have run for, a lower bound: a guest that idles by polling reads as busy. It is meaningless where `idleAvailable` is `false`.
- `busyFraction` and `busyVcpus` are the vCPU threads' on-CPU time. `preemptShare` is the part of the time the vCPUs wanted to run that they were preempted. `unaccountedFraction` is the share of capacity that was neither halted nor on a CPU: vCPUs offline in the guest, or idling without HLT. `runqueueDelayP99Ns` is the worst vCPU's run-queue delay.
- `advice[].kind` is one of `overprovisioned`, `starved`, `nearly_idle`, `no_change`, `idle_unavailable` and `not_enough_data`. Under 20 seconds of history, or a VM the kvm and sched programs have not measured, or one with no known vCPU thread, is `not_enough_data` with the reason in `summary`. `confidence` is `low` for a window under three minutes.

### `GET /api/v1/recorder`

`?vm=<name>&window=<dur>`. The bounded per-VM flight recorder: the newest 4096 events for each VM, replayed by time.

```json
{ "window": "30s", "events": [ ... ] }
```

`events` are as under [Events](#events-and-the-stream), oldest first for one VM. Without `vm`, every VM's events are returned, grouped by VM in no particular VM order. A window that does not parse, or is not positive, is not an error: the default of 60 seconds is used, and `window` says which.

## Events and the stream

An event carries `seq` (assigned by the daemon, only grows), `product: "shukra"`, `kind`, `ts`, `vm` (`name`, `uuid`, `runtime`), `attribution`, `guest_attributed`, and the fields its kind uses. Empty fields are left out.

```json
{
  "seq": 2,
  "product": "shukra",
  "kind": "guest_dns",
  "ts": "2026-09-20T14:58:28.112327Z",
  "vm": { "name": "payment-prod-03", "uuid": "5c1d9f0e-7a4b-4c1e-9b1a-2f6d3e8a4c10", "runtime": "libvirt" },
  "attribution": "guest-tap",
  "guest_attributed": true,
  "src": "10.20.0.14",
  "dst": "10.20.0.2",
  "dport": 53,
  "proto": "udp",
  "iface": "vnet4",
  "dns_name": "updates.example.com",
  "qtype": "A"
}
```

| Kind | What it is | Attribution |
|---|---|---|
| `exec`, `exit` | A child of a watched VMM started or ended: QEMU, or a FluxVM backend. `comm`, `ppid` | `qemu-process` |
| `tcp_connect`, `tcp_retransmit` | The VMM's own sockets, not the guest. The string is `qemu-process` for every backend | `qemu-process` |
| `block_slow`, `sched_delay` | A request or wakeup slower than the sample threshold. `latency_ns` | `qemu-process` |
| `guest_connect` | The guest sent a TCP SYN. `src` is the guest, `dst` and `dport` where to, `proto: "tcp"`, `iface`, `blocked`, and `policy` (`audit` or `enforce`) when the VM's [egress policy](egress-policy.md) judged it to be outside it | `guest-tap` |
| `guest_flow` | The guest started a new UDP flow. `proto: "udp"`; `policy` as above | `guest-tap` |
| `guest_inbound` | A TCP SYN was sent **to** the guest. `src` is the peer, `dst` the guest, `dport` the guest port | `guest-tap` |
| `guest_dns` | The guest asked for a name over UDP port 53. `dns_name` (lower-case), `qtype`, `src` the guest, `dst` the resolver, `dport: 53`, `blocked`, and `dns_truncated` when the name did not fit. Omitted entirely under `-dns-events=false` | `guest-tap` |
| `guest_tls` | The guest sent a TLS ClientHello. `sni` (lower-case, absent when there is none), `alpn`, `tls_version`, `ja3` (only for a whole hello), `ech`, `tls_truncated`, `src` the guest, `dst` the server, `dport`, `blocked`. See [TLS server names](tap.md#tls-server-names). Omitted under `-tls-events=false` | `guest-tap` |
| `vmm_file_open` | A QEMU process, or a program it started, opened a file. `path` (as given; made absolute when a relative one could be resolved), `comm` the program, `pid`, `write`, `syscall`, `detail`. A steady-state VMM opens nothing. See [VMM tripwires](vmm-tripwires.md). Omitted under `-vmm-tripwires=false` | `qemu-process` |
| `vmm_syscall` | The same made `ptrace`, `process_vm_*`, `mount`, `unshare`, `setns`, a module load or a kexec load (`syscall`, `detail`), or more calls in a second than the tripwire reports (`syscall: "flood"`, `count` unreported) | `qemu-process` |
| `detection` | A rule fired. `rule`, `severity`, `message`, and the attribution of the event that triggered it | as the trigger |
| `vm_start`, `vm_stop` | A VMM process appeared or went away | `qemu-process` |
| `netlink_link`, `netlink_address`, `netlink_route`, `netlink_neighbor` | A host link, address, route or neighbor changed. The fields are under `netlink` (`action`, `object`, and the ones that notification carries: `interface`, `address`, `destination`, `gateway`, `oper_state`, `state`, and the rest in [Netlink](netlink.md)). No VM. Omitted under `-netlink-events=false`; a link change still refreshes tap discovery | `host-netlink` |
| `netlink_error` | The Netlink socket overran or the kernel reported an error. `netlink.error` is the signed errno (`ENOBUFS` is `-105`) | `host-netlink` |

`guest_attributed` is `true` only for an event seen on a VM's tap **and** naming a VM in the current scan. A tap no VM owns gives `unattributed`, never a guessed name.

Shukra raises detections of its own as well as your rules' and the built-in ones: `baseline-forgotten`, `action-proposed`, `action-executed`, `action-refused`, `action-rejected`, `action-expired`, `action-released` and `action-dry-run`, and `policy-applied`, `policy-confirmed`, `policy-removed` and `policy-reverted`, and `egress-policy-audit` and `egress-policy-blocked` for a connection outside a VM's policy. They go to every alert sink like any other.

### `GET /api/v1/events`

`?since=<seq>&vm=<name>`. Events newer than `seq`, so a poller never misses one or repeats one.

```json
{ "seq": 6, "events": [ { "seq": 5, "kind": "guest_tls", ... }, { "seq": 6, "kind": "block_slow", ... } ] }
```

`seq` is the newest sequence number the daemon has issued, whatever the filter. `since` that is not an unsigned integer is `400 since must be an unsigned integer`. The daemon keeps 2048 events in all, with a share reserved for each kind so a flood of one cannot push out the others (see [architecture](architecture.md#state-windows-and-history)). Ones that have aged out are not returned. With `-data-dir` the counter continues past the highest restored value; without it, it starts again from 0 after a restart, so a client whose cursor is ahead of the `seq` it gets back should start over (`shukractl watch` does).

### `GET /api/v1/stream`

`?since=<seq>&vm=<name>`, or a `Last-Event-ID` header. The same events as server-sent events. It needs a key like any other `GET`, and the read-only key is enough.

```text
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

id: 41
event: event
data: {"seq":41,"product":"shukra","kind":"guest_dns","ts":"2026-09-20T14:58:28.112327Z", ...}

: keepalive
```

- Each frame is `id: <seq>`, `event: event` and `data: <the event as one line of JSON>`, then a blank line.
- On connect it sends every held event newer than the cursor, then follows. `since` in the query wins; if it is absent or 0 the `Last-Event-ID` header is used; with neither, it starts with everything the daemon still holds (up to 2048 events), so pass the last `seq` you have.
- A line that starts with `:` is a comment, sent every 15 seconds so a proxy does not close an idle stream. `X-Accel-Buffering: no` asks nginx not to buffer it.
- A reconnect resumes from `Last-Event-ID`, which a browser `EventSource` sends by itself. A `since` or `Last-Event-ID` that is not an unsigned integer is `400`.
- The daemon does not close the stream. It ends when the client goes away.

### `GET /api/v1/detections`

`?vm=<name>`. `{"detections": [...]}`: the events of kind `detection` the daemon holds, oldest first, capped at 2048 like events, and restored from `-data-dir` after a restart. `[]` when there are none.

## Security and isolation

### `GET /api/v1/security`

`?vm=<name>`.

```json
{
  "vm": "payment-prod-03",
  "detections": [ ... ],
  "enforcement": "tcx",
  "allowList": ["10.0.0.0/24"],
  "durable": true
}
```

`enforcement` is `tcx` when isolation can be carried out and `not_attached` when it cannot, with the reason in `reason` (which is left out otherwise). `allowList` is the management networks an isolated VM can still reach (`-isolate-allow`). `durable` says isolation survives the daemon: the tap program's links and maps are pinned in the bpf filesystem.

### `GET /api/v1/isolations`

`{"isolations": [...]}`: the audit trail of isolate and release requests, oldest first, newest 2048, and whether each took effect. Restored from `-data-dir`. `[]` when there are none.

### `POST /api/v1/isolate` and `POST /api/v1/release`

Admin key. Body `{"vm": "<name>"}`.

```json
{
  "vm": "batch-07",
  "enforcement": "tcx",
  "applied": true,
  "taps": ["vnet5"],
  "reason": "Traffic to and from vnet5 is dropped, except ARP, IPv6 neighbour discovery and 10.0.0.0/24. It stays enforced if shukrad stops or crashes. Lift it with `shukractl release`, or with the daemon down, `shukrad -detach-all`.",
  "audit": { "ts": "2026-09-20T14:58:40Z", "actor": "key=admin:f72c1a role=admin op=isolate label=shukractl remote=127.0.0.1:9 req=abc", "action": "isolate", "vm": "batch-07", "result": "applied" }
}
```

**The status code is `200` even when the request is refused.** Read `applied`: it is `true` only after the kernel took the change on every tap of the VM. `audit.result` is the detail:

| `audit.result` | Means |
|---|---|
| `applied` | Every tap took it |
| `partial` | Some taps took it and some did not; what took effect is kept, because a half-isolated VM is safer left contained. `reason` names the taps |
| `failed` | Nothing changed. `reason` says why |
| `refused` | Not attempted: no management allow list (`-isolate-allow`), the tap program is not loaded, no VM by that name in the scan, or the VM has no tap (user-mode networking) |
| `recorded_only` | The build has no enforcer; the request was recorded and nothing else happened |

`audit.actor` is the key id (`admin:` or `readonly:` and six hex characters), the role, the operation, the `X-Shukra-Actor` label when one was sent, the source address and the request id. It is not a person's name. The response header `X-Request-Id` is the same id.

Every request is recorded, whether or not it took effect. A missing `vm` or a body that is not JSON is `400 vm is required`. If the kernel applied the change and the audit line or the state file could not be saved, `applied` stays true and the record is marked degraded. `shukractl doctor` then fails `audit-persist`. See [responses](responses.md).

## Learned baselines

Off unless the rules file has a `baselines:` section. See [baselines](baselines.md).

### `GET /api/v1/baseline`

`?vm=<name>&items=1`.

```json
{
  "enabled": true,
  "persisted": true,
  "learn": "24h0m0s",
  "maxAlertsPerDay": 20,
  "note": "What each VM normally does: ...",
  "rows": [
    {
      "vm": "payment-prod-03",
      "since": "2026-09-19T08:58:28Z",
      "learning": false,
      "learnUntil": "2026-09-20T08:58:28Z",
      "counts": [
        { "kind": "destination", "count": 1 },
        { "kind": "dns-suffix", "count": 1 },
        { "kind": "inbound-peer", "count": 1 }
      ],
      "alertsToday": 1,
      "alerts": 1,
      "suppressed": 0
    }
  ],
  "items": [
    { "kind": "destination", "item": "203.0.113.0/24", "first": "2026-09-19T08:58:28Z", "last": "2026-09-20T14:20:11Z" }
  ]
}
```

- `enabled` says whether the rules file has baselines on. When it is `false`, `rows` and `items` are `[]` and nothing else is meaningful (`learn` and `maxAlertsPerDay` are absent).
- `persisted` says whether what was learned survives a restart (there is a `-data-dir`).
- `rows`, per VM: `learning` while its learning period runs (`learnUntil` is when it ends), `counts` of what it learned by `kind` (every kind, zero included: `destination` is a /24 or a /64, `dns-suffix` is the registrable part of a name, `inbound-peer` is a network that connected in), `alertsToday` and `alerts` (first sightings reported after the learning period), and `suppressed` (held back because the VM used its alerts for the day).
- With `vm` and `items=1`, `items` lists what that VM has learned, most recently seen first, at most 500. `[]` for a VM that is unknown or has learned nothing.

### `POST /api/v1/baseline/forget`

Admin key. Body `{"vm": "<name>"}`. Drops what a VM has learned and starts its learning again.

```json
{ "vm": "payment-prod-03", "forgotten": true }
```

`400` for a missing `vm`, `409` when baselines are off, `404` when nothing is kept for the VM. Forgetting is a way to hide a change, so it is recorded as a `baseline-forgotten` detection that names the `X-Shukra-Actor`.

## Egress policy

Which networks each VM may start connections to: learned from its baseline, audited (drops nothing), then enforced with a timer that reverts it unless a person confirms. See [egress policy](egress-policy.md).

### `GET /api/v1/policy`

`?vm=<name>` narrows `policies` to that VM (`[]` if it has none).

```json
{
  "enabled": true,
  "persisted": true,
  "note": "Which networks each VM may start connections to. ...",
  "policies": [
    {
      "vm": "payment-prod-03",
      "mode": "enforce",
      "allow": ["10.20.0.0/24", "203.0.113.0/24"],
      "source": "baseline",
      "by": "shukractl",
      "applied": "2026-09-20T14:55:28Z",
      "present": true,
      "revert": { "until": "2026-09-20T15:05:28Z", "to": "audit" },
      "taps": [
        { "tap": "vnet4", "kernel": "enforce", "checked": 1204,
          "auditPackets": 0, "auditBytes": 0, "droppedPackets": 3, "droppedBytes": 180 }
      ]
    }
  ],
  "orphans": []
}
```

- `mode` is `audit` or `enforce`; a VM with no policy has no entry. `source` is `baseline` or `manual`, `by` is who applied it, `present` says the VM is in the current scan (a policy for a VM that is not running is kept).
- `revert` is present while an enforcing policy waits to be confirmed: `until` is when it goes back, `to` is what to (`off`, or the mode and networks that came before).
- `taps`: per tap, `kernel` is the mode the program is in on that tap, which is the policy's unless something is wrong; `checked` is how many new connections and datagrams were judged; `auditPackets` and `auditBytes` are what audit mode would have dropped; `droppedPackets` and `droppedBytes` are what enforcement dropped.
- `problem` (a sentence) is present when the kernel is not doing what the record says. It is put right on the daemon's next pass.
- `orphans` lists taps the kernel applies a policy on that nobody recorded (`vm`, `tap`, `mode`): the record was lost, or something else set it. `persisted` says records survive a restart. `enabled` is `false` only in a build with no policy engine.

### `GET /api/v1/policy/proposal`

`?vm=<name>` (required). What the VM's learned baseline proposes as its list.

```json
{
  "vm": "payment-prod-03",
  "learning": false,
  "allow": ["203.0.113.0/24"],
  "current": [],
  "added": ["203.0.113.0/24"],
  "removed": [],
  "note": "..."
}
```

`learning` says the VM is still inside its learning period, so the list may be incomplete. `current` is its policy's list now, `added` and `removed` are how `allow` differs from it. `400` without `vm`, `404` when the baseline has not seen the VM, `409` when baselines are off.

### `POST /api/v1/policy/apply`

Admin key.

| Field | |
|---|---|
| `vm` | Required |
| `mode` | Required: `off`, `audit` or `enforce`. `off` lifts the policy, as `remove` does |
| `allow` | Networks the VM may start connections to: CIDRs or bare addresses (a /32 or /128), IPv4 or IPv6, at most 1024. With neither `allow` nor `fromBaseline`, a VM that has a policy keeps its list |
| `fromBaseline` | `true` takes the list from what the VM has been seen to talk to. Needs baselines on |
| `confirm` | How long an enforcing policy stands before it goes back to what it replaced unless confirmed: `30s` to `24h` |
| `permanent` | `true`: no timer. Give `confirm` or `permanent` to enforce, not both |

```json
{ "policy": { "vm": "payment-prod-03", "mode": "audit", "allow": ["203.0.113.0/24"], "source": "baseline", "by": "shukractl", "applied": "2026-09-20T14:55:28Z", "present": true, "taps": [ ... ] } }
```

Enforcing needs the management allow list (`-isolate-allow`), a `-data-dir` (the kernel keeps enforcing without the daemon, so the record has to survive) and a non-empty list. Errors carry the reason as text: `400` for a request that is wrong (a bad mode, network or duration, no list, enforcing with neither or both of `confirm` and `permanent`), `404` when no VM by that name is in the scan, `409` when it is well formed and refused (no tap, tap program not loaded, no allow list, no `-data-dir`, an empty list to enforce), `500` when the record could not be saved or the tap program did not take it (the change is put back).

### `POST /api/v1/policy/confirm` and `POST /api/v1/policy/remove`

Admin key. Body `{"vm": "<name>"}`. The answer is `{"policy": {...}}`. `confirm` makes an enforcing policy stay (`409` when nothing waits, `404` when the VM has no policy). `remove` lifts a policy, and puts right a tap that applies one nobody recorded; its answer has `mode: "off"`. `404` when the VM has no policy and the kernel has none either.

## Responses

What responses decided to do when a detection fired. Off unless the rules file has a `responses:` section. See [responses](responses.md).

### `GET /api/v1/actions`

`?all=1`.

```json
{
  "enabled": true,
  "pending": 1,
  "note": "What responses decided to do when a detection fired. ...",
  "actions": [
    {
      "id": "a-3",
      "vm": "payment-prod-03",
      "response": "contain",
      "mode": "propose",
      "rule": "vmm-opened-file",
      "severity": "high",
      "message": "payment-prod-03's QEMU process opened /etc/shadow",
      "created": "2026-09-20T14:56:28Z",
      "expires": "2026-09-20T15:26:28Z",
      "status": "pending",
      "decided": "0001-01-01T00:00:00Z",
      "releaseAt": "0001-01-01T00:00:00Z",
      "released": "0001-01-01T00:00:00Z"
    }
  ]
}
```

`enabled` says whether the rules file has responses. `pending` is how many wait for a person. `actions` lists only the pending ones, or with `all=1` everything held (up to 500), newest first.

| Field | |
|---|---|
| `id` | `a-<n>` |
| `vm`, `response`, `mode` | The VM, the response's name and its `mode`: `propose` or `enforce`. `dryRun: true` is present on a dry run |
| `rule`, `severity`, `message` | The detection that set it off |
| `created`, `expires` | When it was made, and when a proposal lapses if nobody decides |
| `status` | `pending`, `executed`, `released`, `refused`, `rejected`, `expired` or `dry_run` |
| `decided`, `decidedBy` | When it was decided and by whom: `admin:<6 hex> (<label>)` for a person, or `auto:<response>:<id>` for an automatic one. `keyId`, `role`, `label`, `remote`, `requestId` and `op` are on the same object when the call came from the API |
| `result` | What the isolate request answered, or why it was not made |
| `guardrail` | Which guardrail refused it (`never_isolate`, `isolate_unavailable`, `max_per_hour`, `isolate_refused`) |
| `releaseAt`, `released` | When an isolation releases itself, and when it did |

### `POST /api/v1/actions/<id>/approve` and `.../reject`

Admin key. No body. Approving isolates the VM, after the guardrails are checked again. Rejecting does nothing to the VM. `decidedBy` is the key id, not the `X-Shukra-Actor` header alone.

```json
{ "action": { "id": "a-3", "status": "executed", "result": "isolated: Traffic to and from vnet4 is dropped ...", ... } }
```

| Status | When | Body |
|---|---|---|
| `200` | Decided | `{"action": {...}}` |
| `404` | No action with that id | text |
| `409` | The action is not waiting, it has expired, a guardrail refused it, or the isolate itself was refused | `{"error": "...", "action": {...}}` |
| `409` | No responses are configured | text: `no responses are configured: the rules file has no responses section` |

### `GET /api/v1/actions/<id>/incident`

The incident bundle captured when the action was made, exactly as `GET /api/v1/incident` would have returned it then. `404` for an unknown id, or when nothing is kept for it. The newest 50 bundles are held in memory. With `-data-dir` the newest 200 are also kept on disk (mode 0600), so an older action's bundle survives a restart.

## Metrics

`GET /metrics` is Prometheus text (`text/plain; version=0.0.4`) and needs a key, so give Prometheus the read-only key.

```yaml
scrape_configs:
  - job_name: shukra
    authorization:
      credentials_file: /etc/prometheus/shukra-readonly-key
    static_configs:
      - targets: ["hv-01:30970"]
```

A row that is not measured has no series, so an absent series means "not measured", not zero. VM names come from the QEMU command line and are escaped in label values. Latency histograms are cumulative Prometheus histograms with a fixed `le` set (128 ns to about 137 s, then `+Inf`); they have `_bucket` and `_count` and **no `_sum`**, because the kernel keeps buckets and not a total, and a sum from bucket midpoints would be invented. Use them with `histogram_quantile(0.99, sum by (le, vm) (rate(..._bucket[5m])))`. Queries: [signals](signals.md) and the [tutorial](tutorials/08-lost-traffic.md).

| Series | Type | Labels | Present when |
|---|---|---|---|
| `shukra_vms` | gauge | | always. VMs in the last scan |
| `shukra_program_attached` | gauge | `program` (`kvm`, `sched`, `block`, `net`, `vmm`, `drops`, `tap`) | always. 1 when attached |
| `shukra_events_total` | counter | | always. Events stored since the daemon started |
| `shukra_detections` | gauge | | always. Detections held in memory |
| `shukra_detections_suppressed_total` | counter | | always. Detections held back as repeats |
| `shukra_alert_sent_total`, `shukra_alert_failed_total`, `shukra_alert_dropped_total` | counter | `sink` | a sink is configured. Delivered, failed after retries, dropped because the queue was full |
| `shukra_kvm_exits_total` | counter | `vm` | the VM is measured |
| `shukra_kvm_exits_by_reason_total` | counter | `vm`, `reason`, `name` | measured. `name` only on Intel |
| `shukra_kvm_exit_handling_seconds_total` | counter | `vm`, `reason`, `name` | measured, reason with time. A halt's time is guest idle |
| `shukra_kvm_exit_latency_seconds` | histogram | `vm` | measured. Halts excluded |
| `shukra_sched_on_cpu_seconds_total` | counter | `vm` | measured |
| `shukra_sched_wakeup_delay_seconds_total` | counter | `vm` | measured |
| `shukra_sched_runqueue_delay_seconds` | histogram | `vm` | measured |
| `shukra_sched_vcpu_preempted_seconds_total` | counter | `vm` | measured, and never for `_host` |
| `shukra_sched_vcpu_preempted_by_seconds_total` | counter | `vm`, `by` (`vm:<name>` or a command name) | measured, one series per preemptor with time |
| `shukra_block_ops_total`, `shukra_block_bytes_total` | counter | `vm`, `op` (`read`, `write`) | the VM did block I/O |
| `shukra_block_latency_max_seconds` | gauge | `vm`, `op` | as above. Racy across CPUs |
| `shukra_block_latency_seconds` | histogram | `vm`, `op` | service time, issue to completion |
| `shukra_block_queue_seconds` | histogram | `vm`, `op` | time in the host queue before the device took the request |
| `shukra_block_errors_total` | counter | `vm`, `op` | completions with a non-zero status |
| `shukra_reclaim_stalls_total`, `shukra_reclaim_seconds_total` | counter | `vm` | direct reclaim in the VMM process |
| `shukra_reclaim_seconds` | histogram | `vm` | the same stalls |
| `shukra_oom_kills_total` | counter | `vm` | OOM kills of a VMM process |
| `shukra_tcp_connects_total`, `shukra_tcp_retransmits_total` | counter | `vm` | one per known VM (and `_host`), zero included. **The QEMU process's** sockets, not the guest's |
| `shukra_tap_bytes_total`, `shukra_tap_packets_total` | counter | `vm`, `tap`, `direction` (`from_guest`, `to_guest`) | a VM tap is traced |
| `shukra_tap_dropped_packets_total` | counter | `vm`, `tap` | as above. What Shukra dropped |
| `shukra_tap_isolated` | gauge | `vm`, `tap` | as above. 1 while isolated |
| `shukra_tap_connect_attempts_total`, `shukra_tap_connect_retransmits_total` | counter | `vm`, `tap`, `direction` (`out`, `in`) | as above |
| `shukra_tap_connect_outcomes_total` | counter | `vm`, `tap`, `direction`, `result` (`accepted`, `refused`, `timed_out`, `blocked` out; `accepted`, `refused`, `ignored`, `blocked` in) | as above |
| `shukra_tap_handshake_seconds` | histogram | `vm`, `tap` | the tap program reports a handshake histogram for the tap |
| `shukra_tap_kernel_drops_total` | counter | `vm`, `tap`, `reason` | the drops program is measuring. The Shukra-versus-other split is on `trace/drops` only, because it is a difference of two counters read a moment apart and can dip |
| `shukra_baseline_learning` | gauge | `vm` | baselines are on. 1 while learning |
| `shukra_baseline_items` | gauge | `vm`, `kind` (`destination`, `dns-suffix`, `inbound-peer`) | baselines are on |
| `shukra_baseline_new_total`, `shukra_baseline_suppressed_total` | counter | `vm` | baselines are on. First sightings reported, and held back over the daily limit |
| `shukra_actions_pending` | gauge | | responses are configured. Proposals waiting for a person |
| `shukra_actions` | gauge | `status` (`pending`, `executed`, `executed_audit_degraded`, `released`, `refused`, `rejected`, `expired`, `dry_run`) | responses are configured. Held in memory, by status |
| `shukra_audit_persist_failures_total` | counter | | an isolate or enforce took effect and the audit line or state file was not saved |
| `shukra_tap_attach_seconds` | histogram | `vm` | a tap went from uncovered to covered. Recorded once per transition |
| `shukra_egress_policy_mode` | gauge | `vm`, `tap` | the VM has a policy. 0 off, 1 audit, 2 enforce, as the kernel has it |
| `shukra_egress_policy_unconfirmed` | gauge | `vm` | the VM has a policy. 1 while an enforcing policy waits to be confirmed |
| `shukra_egress_checked_total`, `shukra_egress_audit_packets_total`, `shukra_egress_audit_bytes_total`, `shukra_egress_dropped_packets_total`, `shukra_egress_dropped_bytes_total` | counter | `vm`, `tap` | the VM has a policy |

There is no series for events that carry names (`guest_dns`, `guest_tls`), for VMM tripwires, or for the doctor. Alert on the detections instead, or on `shukra_detections` and the alert-sink series.

## Errors

| Code | When | Body |
|---|---|---|
| `400` | A bad parameter or body: `since` that is not an unsigned integer, a `window` or `at` outside its range, a missing `vm` where it is required, a body that is not JSON | text, one sentence |
| `401` | No key, or the wrong one | `{"error": "unauthorized"}` |
| `403` | The read-only key on a `POST` | `{"error": "this key is read-only"}` |
| `404` | An unknown route, a VM or policy that is not there, an action or bundle that does not exist | text |
| `405` | The route does not take that method | text, with `Allow` |
| `409` | Refused for a reason about the current state: baselines or responses off, a policy request the guardrails refuse, a proposal that is not waiting | text, or `{"error", "action"}` for a decision |
| `500` | A policy record could not be saved or a tap did not take it | text |
| `503` | `/readyz` before the first scan | the `/readyz` body |

Errors other than `401`, `403` and a refused decision are plain text (`text/plain`), not JSON. `shukractl` prints them as `error: <METHOD> <path>: <body>`. A VM name that matches nothing is `200` with an empty result, except where the route acts on it (`policy/apply`, `baseline/forget`, `actions/<id>/...`), which is `404`. `isolate` and `release` are `200` even when refused: read `applied`.
