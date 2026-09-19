# Shukra

<p align="center">
  <img src="docs/shukra-social.png" alt="Shukra — eBPF runtime intelligence for KVM" width="100%">
</p>

**eBPF-powered runtime intelligence and security for KVM.**

Shukra sits on the hypervisor and watches every QEMU/KVM workload from outside the guest. There is no agent to install in the VM. The daemon attaches kernel traces, joins them to the QEMU process, and gives an operator a console and a CLI that say what they know — and what they do not.

Observe. Protect. Explain.

| | |
|---|---|
| Daemon | `shukrad` — privileged, attaches traces, serves the API and console |
| CLI | `shukractl` — talks to the API only, never loads BPF |
| Console | `http://<hypervisor>:30970` |
| Module | `github.com/zyvorai/shukra` |
| License | [Apache-2.0](LICENSE) |

## What you get in 0.1

Five observation programs. Hot paths stay in maps. The ring buffer is only for discrete events.

| Program | Hooks | What it records |
|---|---|---|
| `kvm` | `kvm_exit`, `kvm_entry`, `kvm_mmio`, `kvm_pio` | Exit counts by reason, exit handling time (histogram, halts excluded) and time per reason |
| `sched` | wakeup, switch, exec, exit | On-CPU time, run-queue delay (histogram, per thread), exec and exit events for QEMU children |
| `block` | `block_rq_issue`, `block_rq_complete` | Latency histogram, requests, bytes and the slowest request, per direction |
| `net` | `tcp_v4_connect`, `tcp_v6_connect`, sampled `tcp_retransmit_skb` | Exact connect counts (IPv4 and IPv6) and 1-in-64 retransmit samples |
| `tap` | TCX on each VM tap (Linux 6.6+) | The guest's own traffic: per-tap counters, an event per TCP connect and per new UDP flow, and isolation |

Percentiles come from log2 buckets and can read up to 2x high. See [What each program measures](docs/signals.md) for the caveats.

Identity comes from the QEMU command line (`-name` / `guest=`, `-uuid`, `ifname=`). A PID that is not a QEMU thread group rolls up to `_host` as `unattributed`. It is never given a made-up VM name.

## What this release will not pretend

- Host `tcp_v4_connect` and `tcp_v6_connect` are **QEMU-process** traffic, so those events are `guest_attributed: false`. Only events seen on a VM's tap, by the [tap program](docs/tap.md), are `guest_attributed: true`, and only for a tap that belongs to a VM in the scan.
- CPU steal and which process inside the guest made a connection are not measured.
- `shukractl isolate` really drops the VM's tap traffic, but only with an explicit management allow list (`-isolate-allow`), and `applied` is `true` only after the kernel took the change. Without an allow list it is refused. It needs Linux 6.6 or newer. Enforcement is pinned in the kernel, so it survives a daemon crash or restart, and `shukrad -detach-all` lifts it. See [what is left](docs/roadmap-taptrace.md).
- A build without root, clang, or `/sys/kernel/btf/vmlinux` still serves discovered VMs and reports every program **detached**. It does not invent counters.

PacketWolf and Zeus OS are the intended consumers of this JSON. They are not in this repository.

## Quick start

Go 1.25+ and Node 22 for the console.

```bash
make build
make web
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist
./bin/shukractl status
```

If `SHUKRA_API_KEY` is unset, the daemon uses the dev token `shukra` and says so on stderr. Open the console and sign in with that token.

On a Mac, or any host without BTF, programs stay detached. VM discovery from `/proc` still works. To attach traces you need Linux, clang, bpftool, and kernel BTF — see [Attach traces](docs/tutorials/02-attach-traces.md).

## Deploy a hypervisor

Same entrypoint shape as Netra: host, then user. Shukra is a systemd unit on the hypervisor, not a Helm chart. eBPF has to run where the VMs run.

```bash
./scripts/deploy-remote.sh 10.0.1.5 sus
```

That rsyncs the tree, builds the console and the CO-RE objects, installs `shukrad` and `shukractl` to `/usr/local/bin`, and starts `shukra.service` on `0.0.0.0:30970`. Full walkthrough: [Deploy a hypervisor](docs/tutorials/03-deploy.md).

## Operator loop

```bash
shukractl status
shukractl vms
shukractl trace kvm --vm osboxes-debian
shukractl explain osboxes-debian
shukractl doctor
shukractl recorder osboxes-debian --window 60s
shukractl watch --json
```

`~/.shukra/env` is loaded when the variable is not already set. `SHUKRA_URL` defaults to `http://127.0.0.1:30970`.

```text
shukractl  →  HTTP  →  shukrad  →  tracepoints / kprobes
                              ↘  /proc QEMU scan
```

The CLI never attaches a program. Pin paths, if a later loader adds them, stay under `/sys/fs/bpf/shukra`.

## Monitor the daemon

| Endpoint | Auth | |
|---|---|---|
| `GET /healthz` | none | Process is up |
| `GET /readyz` | none | `200` after the first scan, `503` before. Body has attached and total programs |
| `GET /metrics` | bearer | Prometheus text. A VM with no measured counters has no series, not a zero |
| `GET /api/v1/events?since=<seq>` | bearer | Events newer than `seq`. Every event carries a `seq` that only grows |
| `GET /api/v1/stream` | bearer | Server-sent events. Resume with `Last-Event-ID` or `?since=` |
| `GET /api/v1/isolations` | bearer | Audit trail of isolate and release requests, and whether each took effect |
| `POST /api/v1/isolate`, `POST /api/v1/release` | admin key | Isolate or release a VM. Refused without a management allow list |
| `GET /api/v1/trace/tap` | bearer | Per-tap traffic from the guest's point of view |

### Keep state across restarts

By default everything is in memory. `shukrad -data-dir /var/lib/shukra` (the systemd unit sets it) keeps:

| File | Written | Restored |
|---|---|---|
| `detections.jsonl` | on every detection | last 2048 |
| `isolations.jsonl` | on every isolate request | last 2048 |
| `recorder.json` | every minute and on clean shutdown | the per-VM flight recorder |

Counters and the event list are not saved: they are read from the kernel or rebuilt. After a crash the recorder can be up to a minute behind, detections and isolations are not. Each log rolls to `.1` at 16 MiB. The directory is `0700`, files `0600`, because they name VMs and destinations. Restored events are re-normalized on load, so an edited file cannot claim guest attribution.

`systemctl reload shukra` re-reads the detection rules. A bad file keeps the previous rules. An empty `SHUKRA_API_KEY` uses the dev token and warns; `-no-auth` is the only way to serve without a key.

## Architecture

```text
┌──────── hypervisor ────────┐
│  qemu-system  qemu-system  │
│         ▲          ▲       │
│   kvm / sched / block / net│  eBPF, CO-RE, maps + ring
│              │             │
│           shukrad          │  identity, recorder, detections
│         :30970 API         │
└────────────┬───────────────┘
             │ bearer
     ┌───────┴────────┐
  shukractl        console
```

Events that leave the daemon carry `product: "shukra"`. A joined event has `attribution: "qemu-process"`. An unowned PID has `attribution: "unattributed"`.

## Tutorials

| | |
|---|---|
| [Run it locally](docs/tutorials/01-run-locally.md) | Build, token, console, fixture mode |
| [Attach traces](docs/tutorials/02-attach-traces.md) | clang, BTF, `make generate`, `-tags shukrabpf` |
| [Deploy a hypervisor](docs/tutorials/03-deploy.md) | `deploy-remote.sh`, systemd, what to check |
| [Operator CLI](docs/tutorials/04-shukractl.md) | status, traces, explain, recorder, isolate |
| [Console](docs/tutorials/05-console.md) | Pages, the host banner, what Apply does not do |
| [Detection rules](docs/tutorials/06-watchlist.md) | Destinations, ports, thresholds, suppression, what a detection means |
| [Alert sinks](docs/tutorials/07-alert-sinks.md) | Signed webhook, syslog, JSONL file |

Reference: [shukractl](docs/shukractl.md) · [Signals](docs/signals.md) · [Attribution](docs/attribution.md) · [Guest traffic and isolation](docs/tap.md) · [Tap: what is left](docs/roadmap-taptrace.md) · [Security](SECURITY.md)

## Development

```bash
make test          # go test ./...
make web           # npm ci, unit tests, production build
make generate      # no-op without clang and /sys/kernel/btf/vmlinux
make test-kernel   # load the programs into this kernel and check the counters (root, Linux)
make test-tap      # guest traffic and isolation in a network namespace (root, Linux 6.6+)
make dist          # release tarball and .deb for this architecture (Linux)
```

Default `go build` does not link CO-RE objects, so CI and macOS stay green. The Linux tag is `shukrabpf`. A missing KVM tracepoint detaches only the `kvm` program.

```bash
cd web && VITE_FIXTURE=1 npm run dev
```

Fixture mode is a local console with no daemon. It is not live data.

## License

Apache-2.0. Copyright 2026 Zyvor. See [LICENSE](LICENSE).
