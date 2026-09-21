# Operator CLI

`shukractl` is the only thing you should need on a laptop once a hypervisor is running `shukrad`. It does not load BPF. It sends `Authorization: Bearer` and `X-Shukra-Actor: shukractl`. The header is a client label. The audit record names the key that authenticated (`admin:` plus six hex characters), with that label beside it.

## Point it at the daemon

```bash
export SHUKRA_URL=http://10.0.1.5:30970
export SHUKRA_API_KEY=shukra
```

Or write `~/.shukra/env` and let the CLI load it when the variable is unset:

```bash
SHUKRA_URL=http://10.0.1.5:30970
SHUKRA_API_KEY=shukra
```

`SHUKRA_SKIP_DOTENV=1` ignores that file. `NO_COLOR=1` or `SHUKRA_CLI_COLOR=false` turns color off. `SHUKRA_CLI_NO_BANNER=1` hides the banner. HTTPS to loopback skips verify unless you set `SHUKRA_TLS_INSECURE`; for a private CA on another host use `SHUKRA_CA_FILE=/path/ca.pem` and `SHUKRA_URL=https://...`.

Install onto your PATH:

```bash
shukractl install-cli --prefix "$HOME/.local"
shukractl version
```

`install-cli` prints `installed /home/you/.local/bin/shukractl`. Put that directory on `PATH`.

## The board

```bash
shukractl status
shukractl status --json
shukractl programs
shukractl vms
shukractl vms --json
```

`status` is the one screen to trust first: product, version, mode `observe`, VM count, how many of the eight programs attached, detection count. The last line is the boundary, not a slogan: it says whether guest tap attribution is attached.

```text
SHUKRA
  product     shukra
  version     v1.2.3
  tagline     eBPF-powered runtime intelligence and security for KVM
  mode        observe
  vms         10
  programs    8/8 attached
  detections  3
  observe: host traces, and guest traffic on the VM taps (10 taps via tcx, enforcement survives a daemon restart)
```

`--json` is the form to pipe. Human boards are for a TTY. `status --wait` retries for up to two minutes, which is how the deploy script waits for a restarting daemon.

## Traces

```bash
shukractl trace list
shukractl trace kvm --vm osboxes-debian
shukractl trace sched --vm osboxes-debian --json
shukractl trace block --vm osboxes-debian
shukractl trace memory --vm osboxes-debian  # direct reclaim and OOM of the VMM, not the guest's memory
shukractl trace net --vm osboxes-debian
shukractl trace tap --vm osboxes-debian      # the guest's own traffic and what became of its connections
shukractl trace drops --vm osboxes-debian    # what the kernel dropped on its tap, and whether it was Shukra
shukractl trace contention --window 5m       # which VM took whose CPU
```

`trace list` names the programs that have a trace view. `vmm` has none: its output is events and detections ([tutorial 11](11-vmm-tripwires.md)).

`trace kvm` is exit, entry, MMIO, and PIO counters for that QEMU process. It is not a per-exit log.

`trace sched` is on-CPU time and run-queue delay, and under each VM a `vCPU preempted:` line: how long the vCPUs were runnable but off a host CPU, over how many preemptions, and who had the CPU (`vm:<name>` for another VM's thread, otherwise a host command name such as `cilium-agent`). It is the host's view of losing the CPU, not the guest's steal counter: see [vCPU preemption](../signals.md#vcpu-preemption).

`trace contention` is `trace sched` joined across VMs: for each VM, how much of its preempted time other VMs took (and which), how much its own threads took, and which host tasks took the rest; then, for each VM that took CPU from others, what it was doing meanwhile (on-CPU time and KVM exits over the same window). `--window 5m` widens it. `explain` names a `noisy_neighbour` when one other VM accounts for at least half of a VM's preempted time. It is the host's view, and a yield counts as preemption (see [vCPU preemption](../signals.md#vcpu-preemption)).

`trace net` is `tcp_v4_connect` and `tcp_v6_connect` counted exactly, and a 1-in-64 sample of retransmits. The socket owner is QEMU. Do not brief it as guest egress. The JSON says `guest_attributed: false` and `attribution: "qemu-process"` when the PID joined a VM. The guest's own traffic is `trace tap`, seen on the VM's tap.

`trace tap` is the guest's traffic from its own tap: packets and bytes each way, what isolation dropped, and what became of every TCP connection, both ways (accepted, refused, never answered, blocked, retransmits, and the handshake time). `trace drops` is what the kernel dropped on the tap by its own reason, with Shukra's isolation subtracted. Both are `guest_attributed: true`. See [guest traffic and isolation](../tap.md) and [where packets die](../drops.md), and the [walkthrough](08-lost-traffic.md).

A VM name that does not match is an empty result (`no rows`), not a guessed one.

## Advise: is each VM the right size?

```bash
shukractl advise
shukractl advise --vm osboxes-mint --window 3m
```

For each VM it prints the numbers it stands on (the share of the window its vCPUs were **halted**, **busy** as a percent and as a count of vCPUs, and **preempted**) and then advice, each piece with how sure it is:

- **`overprovisioned`**: two or more vCPUs, halted at least 80% of the time and busy at most 20%. It suggests a size that would leave twice the headroom it used, and notes that fewer vCPUs also means fewer threads competing for host CPUs.
- **`starved`**: busy at least half the time and either preempted for at least 10% of the time it wanted to run or a vCPU waiting 2 ms or more for a CPU. It says to reduce what the VM competes with (pinning, moving a neighbour: see `trace contention`) before adding vCPUs, which would add threads that wait.
- **`nearly_idle`**: one vCPU, halted at least 95%: a consolidation candidate.
- **`no_change`**, with the numbers; **`not_enough_data`** (less than 20 seconds of history, no vCPU thread known, or the programs have not measured it); **`idle_unavailable`** (see below).

The `neither` figure is the share of the vCPUs' capacity that was neither halted nor on a CPU. Where it is large, some vCPUs never execute HLT (offline in the guest, or idling with MWAIT or a polling loop), and `no_change` says that it is not proof the VM is right-sized: on the live hypervisor the three-vCPU VMs read exactly one third or two thirds halted for this reason.

Read it with its caveats. Idleness is **halt time**, so it is a **lower bound**: a guest that idles by polling reads as busy, and halt polling counts as CPU time. Exit reasons are only named on **Intel** hosts, so on another CPU the halted column is `n/a` and nothing about over-provisioning is claimed (starvation does not need it and is still reported). A window under three minutes is a low-confidence sample. It changes nothing: it is advice for a person.

## Doctor

```bash
shukractl doctor            # what needs attention, worst first, each with a fix
shukractl doctor --strict   # exit non-zero on a warning too, to gate a deploy
shukractl doctor --json
```

`doctor` only reads, and every check it can raise is listed, with when it fires and what to do, in [doctor](../doctor.md). It reports how the API is exposed (the well-known dev key, plain HTTP on a non-loopback address, no key at all), whether the kernel supports every program, which programs are detached and why, VMs whose tap it cannot find, or whose named interface is not in this network namespace (a FluxVM guest on the default netns is traced on the host veth and is not one of these), and so cannot see or isolate, whether isolate is enabled and survives the daemon, whether state is kept across a restart, whether an egress policy is orphaned or waiting to be confirmed, whether a response can act, where alerts go, and whether the last detection-file reload failed and left old rules in force. Only findings that need attention are printed, worst first, each with what to change; a clean daemon prints one line. The deploy script runs it at the end. The same audit is `GET /api/v1/doctor`, readable with the read-only key, and it never contains a key. How a FluxVM interface is chosen is in [FluxVM](../tap.md#fluxvm).

## Explain and the flight recorder

`explain <vm>` weighs the last minute by default, not the whole time the daemon has been attached. A disk that was slow an hour ago and is fine now would otherwise hold a lifetime p99 high for good. `--window 5m` looks further back (up to 5 minutes) and `--window lifetime` uses everything. The daemon keeps a small snapshot every 10 seconds for this, so right after a start there is nothing to compare against: below 20 seconds of history it falls back to lifetime and the output says `window: lifetime`, and when less history exists than you asked for it reports the span it really covered. Whether a program is measuring at all is always judged over its lifetime, so a quiet minute is never mistaken for a detached program. The maximum latency is not a rate and cannot be windowed, so it stays lifetime.


```bash
shukractl explain osboxes-debian
shukractl recorder osboxes-debian --window 60s
```

`explain` answers from evidence on hand. The causes it can give are `host_cpu_contention`, `cpu_preempted` (the vCPUs were taken off a host CPU, and it says by whom), `noisy_neighbour` (most of that went to one other VM), `storage_latency`, `kvm_exit_handling`, `tcp_retransmits`, and, from the guest's tap, `guest_traffic_dropped` (something other than Shukra is dropping its packets), `guest_not_reading_nic` and `guest_connects_failing`; otherwise `no_host_cause`, or one of three that say why there is no verdict: `unknown_vm` (no VM with that name), `not_measured` (no kernel program has measured it, so nothing host-side can be said) and, for a past time, `no_history` (nothing stored for that time; see [after the fact](09-after-the-fact.md)), which says the cause may be inside the guest. The missing list is part of the answer: the guest's own CPU steal counter, in-guest process, and guest tap attribution when the tap program is off. If those lines are present, Shukra is telling you it cannot see them.

### A verdict for a past time

An incident is often found an hour after it happened, and the last minute is no help then. With `-data-dir` the daemon stores a coarse snapshot every 5 minutes, and

```bash
shukractl explain osboxes-debian --at 2026-09-20T03:12:00Z --window 30m
shukractl explain osboxes-debian --at -3h          # three hours ago
shukractl incident osboxes-debian --at -3h --out osboxes-incident.json
```

`explain --at` weighs what the counters did in the window ending at that time, from the two stored snapshots around it, and prints how coarse that is (`resolution:`). If nothing is stored for the time it says why: no data directory, nothing that old, the daemon was not running, or not enough before it. It does not guess. `incident` adds the window's detections, the recorder's events and the VM's isolate requests, and `--out` writes a private file to attach to a ticket. See [past verdicts](../shukractl.md#past-verdicts-and-incident-bundles).

`recorder` replays the bounded per-VM ring, default cap 4096, default window 60s. With `-data-dir` the ring is saved every minute and on clean shutdown and reloaded at start; without it the ring starts empty after a restart. Kinds you will actually see: `exec`, `tcp_connect`, `tcp_retransmit`, `block_slow` (at least 10ms), `sched_delay` (at least 20ms), `detection`, process exit, `vm_start` and `vm_stop`, what a VMM opened or called (`vmm_file_open`, `vmm_syscall`; the CLI shows their `path` and `syscall` under `watch`, and leaves the message empty), and, when the tap program is attached, the guest's own `guest_connect`, `guest_flow`, `guest_inbound`, `guest_dns` and `guest_tls` events. The recorder holds the DNS names a guest looked up, so it is as sensitive as the event list: see [SECURITY](../../SECURITY.md). Counters do not each become an event.

```bash
shukractl watch
shukractl watch --json --once
```

`watch` streams discrete events. `--once` prints what is buffered and returns. Host link, address, route and neighbor changes are there too (`netlink_*`, `host-netlink`). A VM tap names that VM; a host interface does not, and lands on the `_host` recorder. A deleted tap, a tap that went down, a removed default route or a failed neighbor is also a detection. See [Netlink](../netlink.md).

## Security and isolation

```bash
shukractl security osboxes-debian
shukractl isolate osboxes-debian
shukractl release osboxes-debian
shukractl rules check /etc/shukra/detections.yaml   # validate a rules file offline
```

`security` is every detection for one VM, and whether isolate can be enforced: the header says `enforcement=tcx` when it can and `not_attached` when it cannot, with the reason. A detection can be a rule of yours (the QEMU process, or, with the tap program, the guest itself, connected to a CIDR in the YAML, or someone connected in: see [the watchlist tutorial](06-watchlist.md)), a first sighting from a [baseline](../baselines.md), a strayed connection under an [egress policy](10-egress-policy.md), a [VMM tripwire](11-vmm-tripwires.md), or a change made through `policy`, `baseline --forget` or a response.

`isolate` is a POST that does something. With the tap program attached and a management allow list configured (`shukrad -isolate-allow ...`), it drops the VM's tap traffic except ARP, IPv6 neighbour discovery and that list, and prints `applied true` with the taps it changed. `release` lifts it. Without an allow list it is refused and prints the reason, and `applied` stays `false`:

```text
ISOLATE  web-01
enforcement   tcx
applied       true
taps          vnet3
...
```

Setting `-isolate-allow` lets whoever holds the admin key cut a VM off. Do it on a host with a real key and TLS, not with the dev key `shukra` over plain HTTP: `shukractl doctor` says which you have. `applied` is the daemon's word, set only after the kernel took the change, so a runbook can trust it. Isolation is pinned in the kernel: it survives a daemon crash or restart, and `shukrad -detach-all` lifts it when the daemon is down. See [Guest traffic and isolation](../tap.md).

## Baselines, responses and egress policy

Three more groups of commands work from what the daemon has learned or decided. Each has a tutorial; this is the map.

```bash
shukractl baseline                          # what each VM has learned as normal, and where its learning period stands
shukractl baseline web-01 --items           # the networks, sites and inbound peers, with first and last seen
shukractl actions                           # what responses proposed and is waiting for a person
shukractl actions --all                     # and what was done or refused
shukractl approve a-3                       # carry out a proposed isolation: this isolates the VM
shukractl reject a-3                        # decline it. Nothing is done
shukractl policy                            # which networks each VM may start connections to
shukractl policy learn web-01               # propose a list from its baseline
shukractl policy apply web-01 --mode audit --from-baseline
shukractl policy apply web-01 --mode enforce --confirm 5m
shukractl policy confirm web-01
shukractl policy remove web-01
```

`baseline` says `off` until the rules file has a `baselines:` section ([detection rules](06-watchlist.md#more-rules)). `actions` says `off` until it has `responses:`. `approve` and `reject` take the id from `actions` (`a-3`), and `approve` isolates a VM, so read the evidence first with `shukractl actions --bundle a-3`. `baseline <vm> --forget` restarts a VM's learning and is recorded as a detection naming who did it. The `policy` group is the whole of [learn, audit, enforce an egress policy](10-egress-policy.md). Everything that changes something (`isolate`, `release`, `approve`, `reject`, `policy apply|confirm|remove`, `baseline --forget`) needs the admin key.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `connection refused` | `SHUKRA_URL` is wrong or the daemon is down. `curl "$SHUKRA_URL/healthz"` answers without a key |
> | `{"error":"unauthorized"}` | The key. On a deployed host it is in `/etc/shukra/env`, and `~/.shukra/api-key` for the user who deployed |
> | `{"error":"this key is read-only"}` | You are using `SHUKRA_READONLY_KEY` for a command that changes something |
> | `x509: certificate signed by unknown authority` | `SHUKRA_CA_FILE=/path/ca.pem`, or `SHUKRA_TLS_INSECURE=true` for a lab |
> | A VM name gives an empty result | The name must match `shukractl vms` exactly. It is never guessed |

Next: the same facts in the [console](05-console.md).
