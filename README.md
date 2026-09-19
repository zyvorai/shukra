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

Four observation programs. Hot paths stay in maps. The ring buffer is only for discrete events.

| Program | Hooks | What it records |
|---|---|---|
| `kvm` | `kvm_exit`, `kvm_entry`, `kvm_mmio`, `kvm_pio` | Exit-reason and MMIO/PIO counters |
| `sched` | wakeup, switch, exec, exit | On-CPU time, wakeup delay, exec and exit events |
| `block` | `block_rq_issue`, `block_rq_complete` | Log2 latency histogram. p50 and p99 are computed in userspace |
| `net` | `tcp_v4_connect`, sampled `tcp_retransmit_skb` | Connects and 1-in-64 retransmits |

Identity comes from the QEMU command line (`-name` / `guest=`, `-uuid`, `ifname=`). A PID that is not a QEMU thread group rolls up to `_host` as `unattributed`. It is never given a made-up VM name.

## What this release will not pretend

- Host `tcp_v4_connect` is **QEMU-process** traffic. `guest_attributed` is always `false`.
- CPU steal, in-guest processes, and packets on the VM tap are not measured. That is the [tap/TCX slice](docs/roadmap-taptrace.md).
- `shukractl isolate` records the decision and returns `applied: false`. No TC, XDP, or Cilium program is attached.
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
shukractl recorder osboxes-debian --window 60s
shukractl watch --json
```

`~/.shukra/env` is loaded when the variable is not already set. `SHUKRA_URL` defaults to `http://127.0.0.1:30970`.

```text
shukractl  →  HTTP  →  shukrad  →  tracepoints / kprobes
                              ↘  /proc QEMU scan
```

The CLI never attaches a program. Pin paths, if a later loader adds them, stay under `/sys/fs/bpf/shukra`.

## Architecture

```text
┌──────── hypervisor ────────┐
│  qemu-system  qemu-system  │
│         ▲          ▲       │
│   kvm / sched / block / net│  eBPF, CO-RE, maps + ring
│              │             │
│           shukrad          │  identity, recorder, watchlist
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
| [Destination watchlist](docs/tutorials/06-watchlist.md) | YAML, severity, what a detection means |

Reference: [shukractl](docs/shukractl.md) · [Attribution](docs/attribution.md) · [Tap/TCX roadmap](docs/roadmap-taptrace.md) · [Security](SECURITY.md)

## Development

```bash
make test          # go test ./...
make web           # npm ci, unit tests, production build
make generate      # no-op without clang and /sys/kernel/btf/vmlinux
```

Default `go build` does not link CO-RE objects, so CI and macOS stay green. The Linux tag is `shukrabpf`. A missing KVM tracepoint detaches only the `kvm` program.

```bash
cd web && VITE_FIXTURE=1 npm run dev
```

Fixture mode is a local console with no daemon. It is not live data.

## License

Apache-2.0. Copyright 2026 Zyvor. See [LICENSE](LICENSE).
