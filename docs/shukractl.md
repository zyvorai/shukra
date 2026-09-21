# shukractl

`shukractl` is the operator CLI for Shukra. It is a client of the daemon's [API](api.md) and nothing more: it does not load BPF, read `/proc` or touch a VM, and every board it prints is a route you could `curl`. Walkthroughs: [tutorials](tutorials/README.md).

```bash
shukractl help                                  # every command, and the environment it reads
shukractl status                                # is the daemon up, what is attached
shukractl doctor                                # what needs attention, worst first
shukractl explain payment-prod-03               # why does this VM look slow
shukractl trace kvm --vm payment-prod-03        # counters for one VM
shukractl isolate payment-prod-03               # drop its tap traffic (admin key)
```

The outputs on this page come from the CLI run against the daemon's own handlers over a fixture of three VMs, trimmed where a line says `...`. Names and addresses are made up. The `advise` example is the exception: the fixture had too little history to advise, so its numbers are illustrative and its layout is what the code prints.

## Connecting

The CLI finds the daemon and the key in this order:

1. The environment.
2. `~/.shukra/env`, a file of `NAME=value` lines (`#` comments; quotes around a value are stripped; no `export` prefix). It only sets a variable that is not already set.
3. For the key only, the first line of `~/.shukra/api-key`.

`SHUKRA_SKIP_DOTENV=1` skips both files. `SHUKRA_URL` defaults to `http://127.0.0.1:30970`.

**The CLI never guesses a key.** If none is found it sends none, and the daemon answers `401`, even a daemon running on its dev key: set `SHUKRA_API_KEY=shukra` for that. The deploy script writes both files on the host it installs, so `shukractl` works there as the user who ran it.

The read-only key (`SHUKRA_READONLY_KEY` on the daemon) is enough for every command except the ones marked **admin** below. Those get `403 this key is read-only` with a read-only key.

Every request carries `X-Shukra-Actor: shukractl`. That header is an optional client label, not a user. The daemon records the key that authenticated, as `admin:` or `readonly:` plus the first six hex characters of SHA-256 of the key, with the label in parentheses when it is a short token (`admin:f72c1a (shukractl)`). The source address, request id, role and operation are on the same record. A request times out after 15 seconds (`watch`'s stream has no timeout), and at most 4 MiB of a response is read.

Flags take their value as the next word: `--window 5m`, not `--window=5m`. A command that names a VM takes it as the first word after the command.

## Commands

Every command that prints a board also takes `--json`. Key order in that output is not guaranteed, so parse it; do not diff it.

### Hypervisor

#### `status [--json] [--wait]`

The daemon board: version, mode, how many programs are attached, VMs and detections held. `--wait` retries every 200 ms for up to two minutes while the daemon starts, printing `waiting for shukrad: <error>` to stderr, and is what the deploy script uses. (Any error is retried, a `401` included.) Route: `GET /api/v1/status`.

```text
SHUKRA
  product     shukra
  version     0.1.0
  tagline     eBPF-powered runtime intelligence and security for KVM
  mode        observe
  vms         3
  programs    7/7 attached
  detections  1
  observe: host traces, and guest traffic on the VM taps (2 taps via tcx, enforcement survives a daemon restart)
```

#### `doctor [--json] [--strict]`

Audits the daemon: how the API is exposed, what is attached, which VMs it cannot see, what is happening to their traffic, and how isolation, persistence, alerts and rules are set up. It only reads. The text form prints every finding that is not `ok`, worst first, each with a fix, and ends with a count that treats `info` as needing attention. `--json` prints every check, `ok` ones too. Exit status: `1` on a `fail`, and with `--strict` on a `warn` too; `info` never fails it. Every check, when it fires and what to do: [doctor](doctor.md). Route: `GET /api/v1/doctor`.

```text
[warn] The API is plain HTTP on a non-loopback address
       The bearer key crosses the network in the clear on 0.0.0.0:30970.
       fix: Add -tls-cert and -tls-key (SHUKRA_EXTRA_ARGS in /etc/shukra/env), or listen on 127.0.0.1.
[warn] 1 proposed isolations are waiting for a decision
       1 propose, 1 enforce, 0 dry run. A proposal lapses if nobody decides.
       fix: shukractl actions, then shukractl approve <id> or reject <id>.
[info] No read-only key
       A scrape or dashboard has to use the admin key, which can also isolate a VM.
       fix: Set SHUKRA_READONLY_KEY and give that to Prometheus.
...
5 checks passed, 8 need attention (worst: warn)
```

#### `programs`

Which of the seven observation programs (`kvm`, `sched`, `block`, `net`, `vmm`, `drops`, `tap`) are attached, how many hooks, and why one is not. Takes `--json`. Route: `GET /api/v1/programs`.

```text
PROGRAMS
  kvm       attached    4 hooks
  sched     attached    4 hooks
  block     attached    2 hooks
  net       attached    3 hooks
  vmm       attached    15 hooks
  drops     attached    1 hooks
  tap       attached    2 taps via tcx, enforcement survives a daemon restart
```

On a build without BPF every line reads `detached` with `CO-RE objects are not linked in this binary`.

#### `install-cli [--prefix DIR]`

Copies this binary to `<DIR>/bin/shukractl` (default `/usr/local`), mode `0755`, through a temporary file and a rename, creating the directory if needed. It needs no daemon. It prints `installed <path>` and `Run: shukractl status`.

```bash
shukractl install-cli --prefix "$HOME/.local"
```

### Trace

#### `trace list`

`trace` alone does the same. Prints what each trace covers, then the `programs` board. It lists `kvm`, `sched`, `block`, `net`, `tap`, `drops` and `contention`; `vmm` has no trace of its own, its output is events and detections (see `watch`).

#### `trace kvm|sched|block|net|tap|drops|contention [--vm NAME] [--json] [--window DUR]`

Per-VM counters from the daemon, one line per VM. `--vm` narrows to one. `--window` applies to `contention` only (`10s` to `5m`, or `lifetime`; default 60 s). A VM whose program is not measuring is shown with zeros, not hidden: check `shukractl programs`, or `--json` for `measured`. Routes: `GET /api/v1/trace/<kind>`.

```text
$ shukractl trace sched
TRACE SCHED
  vm=payment-prod-03  oncpu_ns=112000000000  wakeup_ns=3800000000  wakeups=260000
      vCPU preempted: 30000000000ns over 18000 preemptions  (taken by: vm:batch-07 26000000000ns, kworker/3:1 4000000000ns)
  vm=batch-07  oncpu_ns=380000000000  wakeup_ns=100000000  wakeups=900000
      vCPU preempted: 0ns over 0 preemptions

$ shukractl trace tap
Traffic seen on the host side of each VM tap: from_guest is what the guest sent, to_guest is what was sent to it.
TRACE TAP
  vm=payment-prod-03  tap=vnet4  from_guest=610000000 B/812345 pkts  to_guest=1900000000 B/790001 pkts  dropped=0 pkts  isolated=false
      connects out: 50 attempts = 40 accepted + 6 refused + 3 never answered + 1 blocked  (4 retransmits, handshake p50 262144ns p99 524288ns)
      connects in:  9 attempts = 2 accepted + 3 refused + 4 ignored + 0 blocked  (1 retransmits)

$ shukractl trace drops
TRACE DROPS
  vm=payment-prod-03  tap=vnet4  kernel=21  shukra=0  other=9  guest_not_reading=12
      FULL_RING      12  freed in tun_net_xmit
      OTHERHOST      9  freed in __netif_receive_skb_core

$ shukractl trace contention
TRACE CONTENTION  window=lifetime
  vm=payment-prod-03  preempted=30000000000ns over 18000 preemptions  (other VMs 26000000000ns, its own threads 0ns, host tasks 4000000000ns)
      taken by VM batch-07: 26000000000ns (87%)
      taken by host tasks: kworker/3:1 4000000000ns
  culprits (what each VM did meanwhile)
    vm=batch-07  took=26000000000ns from 1 VMs  its own on-cpu=380000000000ns  exits=1000
```

- `kvm`: exits, entries, MMIO and PIO counts. `--json` has the exit reasons and latency.
- `sched`: on-CPU time, run-queue delay and, for a VM, vCPU preemption and who took the CPU. The `_host` row has no preemption line.
- `block`: requests and p50/p99 latency of the QEMU I/O thread, not the guest filesystem.
- `net`: `tcp_v4_connect` and `tcp_v6_connect` from the **QEMU process**, always `guest_attributed=false`.
- `tap`: the guest's own traffic per tap, and every TCP handshake's outcome. Attempts = accepted + refused + never answered + blocked, plus any still waiting.
- `drops`: what the kernel dropped on each tap, by reason, with Shukra's own subtracted. Says `the drops program is not measuring` when it is not.
- `contention`: who took whose vCPU time, and what the taker did meanwhile.

`trace bogus` and a missing kind print `trace kvm|sched|block|net|tap|drops|contention` and exit `1`.

### Investigate

#### `vms [--json]`

QEMU and FluxVM virtual machines found on the host. `taps=-` means no known tap. Route: `GET /api/v1/vms`.

```text
VMS
  payment-prod-03  runtime=libvirt  pid=4121  uuid=5c1d9f0e-7a4b-4c1e-9b1a-2f6d3e8a4c10  taps=vnet4
  batch-07  runtime=qemu  pid=5200  uuid=b7e0c2a4-1f33-4d0a-8c55-0a9d5e41f7b2  taps=vnet5
  dev-sandbox  runtime=qemu  pid=6100  uuid=0a91c7de-3f10-4b52-a1f4-6d2b8e90c377  taps=-
```

#### `explain <vm> [--window 5m|lifetime] [--at TIME|-90m] [--json]`

Why the VM looks slow: ranked host-side causes with their evidence, and what Shukra cannot see. Live, it weighs the last minute; `--window` is `10s` to `5m`, or `0` or `lifetime`. With `--at` it answers for a past time: see [Past verdicts and incident bundles](#past-verdicts-and-incident-bundles). An unknown VM is a `unknown_vm` finding and exit `0`. Route: `GET /api/v1/explain`.

```text
EXPLAIN  why is this VM slow?  (window: lifetime)
findings (best supported first)
  [high] cpu_preempted: The host took CPU away from this VM's vCPUs. Look at what else is running on those host CPUs: ...
      The vCPU threads were runnable but off a host CPU for 30 s over 18000 preemptions, 21% of the time they wanted to run.
      Taken by: VM batch-07 (26 s), host task kworker/3:1 (4 s).
  [high] noisy_neighbour: Another VM, batch-07, took most of the CPU this VM's vCPUs were denied. ...
      batch-07 took 26 s of the 30 s the vCPUs were preempted (87%). shukractl trace contention shows what batch-07 was doing meanwhile.
  [medium] guest_not_reading_nic: The tap's queue is full, so the host cannot hand this VM the packets it is sent. ...
      12 packets were dropped on tap vnet4 because its queue was full.
  note: Latencies are since the daemon attached, from log2 buckets, so each can read up to 2x high. ...
evidence
  Identity comes from the QEMU command line, not from inside the guest.
  KVM exit counters are present for this thread group.
missing
  CPU steal as the guest counts it (Shukra measures the host's view: how long the vCPUs were preempted)
  in-guest process identity
```

The causes and what each means are in the [API reference](api.md#explain-incident-advice-and-the-recorder). `window:` reads `lifetime` when there was too little history for the window asked; that is stated, not hidden.

#### `incident <vm> [--at TIME|-90m] [--window 15m] [--out FILE] [--json]`

Everything known about a VM around a moment, in one bundle for a ticket: the verdict, the window's detections, what the flight recorder saw, the VM's isolate requests, the allow list and the programs. Without flags it prints a summary. `--out FILE` writes the whole JSON to a file with mode `0600` (it names VMs, addresses and DNS names) and prints `wrote <file> (<n> bytes, mode 0600)`. `--json` prints the JSON to stdout, as the daemon sent it. `--window` is `5m` to `6h`, default 15 minutes. Route: `GET /api/v1/incident`.

```text
INCIDENT  vm=payment-prod-03  at=now  window=15m0s
EXPLAIN  why is this VM slow?  (window: lifetime)
findings (best supported first)
  ...
detections (1)
  2026-09-20T15:05:33.41289Z  high  payment-prod-03's QEMU process opened /etc/shadow
recorder events: 6  isolate requests: 0
the whole bundle: shukractl incident <vm> --out FILE (or --json)
```

#### `advise [--vm NAME] [--window 5m] [--json]`

Is each VM the right size? Per VM, the numbers (vCPUs, halted, busy, preempted) and advice with how sure it is: `overprovisioned`, `starved`, `nearly_idle`, `no_change`, `idle_unavailable` (not an Intel host) or `not_enough_data`. `--window` is `1m` to `5m`, default `5m`. It is advice for a person and changes nothing. Route: `GET /api/v1/advice`.

```text
ADVISE  window=4m58s
  vm=batch-07  vcpus=2  halted=91%  busy=7% (0.1 vCPUs)  preempted=0%  neither=2%
      [medium] overprovisioned: This VM has 2 vCPUs and used about 0.1 of them. 1 would leave it twice the headroom it used. ...
          Over 4m58s its vCPUs were halted 91% of the time they could have run and on a CPU 7%. ...
```

`halted=n/a` means halt time is not named on this CPU. Under 20 seconds of history a VM says `not_enough_data`.

#### `baseline [<vm>] [--items] [--forget] [--json]`

What each VM has learned as normal (networks it talks to, sites it looks up, who connects in) and where its learning period stands. `--items` (with a VM) lists what that VM learned, most recently seen first, at most 500. `baseline <vm> --forget` (**admin**) drops what a VM learned and starts it again; it is recorded as a `baseline-forgotten` detection naming the actor. Off, and it says so, unless the rules file has a `baselines:` section. See [baselines](baselines.md). Routes: `GET /api/v1/baseline`, `POST /api/v1/baseline/forget`.

```text
BASELINE  learning period 24h0m0s, at most 20 new-item alerts per VM per day
  vm=batch-07  learning until 2026-09-21T17:35:33+05:30  (destination 1, dns-suffix 0, inbound-peer 0)  new alerts today 0, held back in all 0
  vm=payment-prod-03  reporting  (destination 1, dns-suffix 1, inbound-peer 1)  new alerts today 1, held back in all 0
```

`WARNING: not kept across a restart (no -data-dir)` is appended to the heading when learning would start over with the daemon.

#### `policy [<vm>] | learn <vm> | apply <vm> ... | confirm <vm> | remove <vm>`

Which networks each VM may start connections to: learned from its baseline, audited (drops nothing), then enforced with a timer that reverts it unless confirmed. See [egress policy](egress-policy.md). Changing anything needs the **admin** key.

| Form | What it does |
|---|---|
| `policy [<vm>] [--json]` | Lists each VM's policy: mode, how many networks and where they came from, who set it, whether it waits to be confirmed, and per tap what the kernel has counted. Names any orphan (a tap enforcing a policy nobody recorded). `GET /api/v1/policy` |
| `policy learn <vm> [--json]` | Proposes a list from the VM's baseline and how it differs from its current policy. `GET /api/v1/policy/proposal` |
| `policy apply <vm> --mode audit\|enforce\|off [--allow a,b \| --from-baseline] [--confirm 5m \| --permanent] [--json]` | Puts a VM under a policy. `--mode` is required. `--allow` takes CIDRs or addresses, comma separated. With neither `--allow` nor `--from-baseline`, a VM that already has a policy keeps its list. Enforcing needs `--confirm <duration>` (30 s to 24 h: it goes back to what it had unless confirmed) or `--permanent`, the management allow list and `-data-dir`. `POST /api/v1/policy/apply` |
| `policy confirm <vm> [--json]` | Keeps an enforcing policy that is waiting. `POST /api/v1/policy/confirm` |
| `policy remove <vm> [--json]` | Lifts a policy, and puts a tap right that enforces one nobody recorded. `POST /api/v1/policy/remove` |

```text
$ shukractl policy
EGRESS POLICY  1 VMs
  payment-prod-03  enforce  2 networks (baseline), set by shukractl at 2026-09-20T15:02:33Z
      UNCONFIRMED: goes back to audit at 2026-09-20T15:12:33Z unless confirmed: shukractl policy confirm payment-prod-03
      vnet4  kernel enforce  judged 1204 new connections, 3 dropped (180 bytes)

$ shukractl policy learn payment-prod-03
POLICY PROPOSAL  payment-prod-03  2 networks
    10.20.0.0/24
    203.0.113.0/24
    + 10.20.0.0/24  (against its current policy)
  audit it first: shukractl policy apply payment-prod-03 --mode audit --from-baseline

$ shukractl policy apply payment-prod-03 --mode enforce --from-baseline --confirm 10m
payment-prod-03: egress policy applied
  payment-prod-03  enforce  2 networks (baseline), set by shukractl at 2026-09-20T15:05:52Z
      UNCONFIRMED: goes back to audit at 2026-09-20T15:15:52Z unless confirmed: shukractl policy confirm payment-prod-03
      vnet4  kernel enforce  judged 0 new connections
```

A refusal is an error with the daemon's reason, and exit `1`: for example `refused: enforcing needs the management allow list (-isolate-allow) ...`. A `PROBLEM` line is printed when the kernel is not doing what the record says.

#### `actions [--all] [--bundle <id> [--out FILE]] [--json]`

What responses decided: the proposals waiting for a person, and with `--all` everything held, newest first. `--bundle <id>` prints the incident bundle an action was made on, as the daemon sent it, and `--out FILE` writes it with mode `0600` instead. Off, and it says so, unless the rules file has a `responses:` section. See [responses](responses.md). Routes: `GET /api/v1/actions`, `GET /api/v1/actions/<id>/incident`.

```text
ACTIONS  1 waiting for a decision
  a-3  pending  vm=payment-prod-03  response=contain (propose)  for vmm-opened-file [high]
      payment-prod-03's QEMU process opened /etc/shadow
      lapses 2026-09-20T15:33:33Z: shukractl approve a-3  or  shukractl reject a-3  (evidence: shukractl actions --bundle a-3)
```

#### `approve <id>` and `reject <id>` (**admin**)

Decide a proposal. `approve` carries out the isolation (the guardrails are checked again) and prints `approved <id>: <result> (<status>)`. `reject` prints `rejected <id>: nothing was done to <vm>`. Either takes `--json` after the id. An unknown id, an action that is not waiting, an expired proposal or a guardrail's refusal is an error and exit `1`. Routes: `POST /api/v1/actions/<id>/approve`, `.../reject`.

```text
approved a-3: isolated: Traffic to and from vnet4 is dropped, except ARP, IPv6 neighbour discovery and 10.0.0.0/24. (executed)
```

#### `recorder <vm> [--window 60s] [--json]`

Replays the flight recorder for one VM: its newest events, one per line as time, kind and message. Route: `GET /api/v1/recorder`.

```text
RECORDER  window=30s
  2026-09-20T15:05:33.412886Z  guest_connect  
  2026-09-20T15:05:33.412887Z  guest_dns  
  2026-09-20T15:05:33.41289Z  detection  payment-prod-03's QEMU process opened /etc/shadow
```

Only some events carry a `message`; `--json` has the rest.

#### `watch [--json] [--once]`

Streams discrete events. It reads what the daemon holds, then follows `GET /api/v1/stream`, and after a disconnect polls once and reconnects (every second), resuming from the last `seq` it saw. It notices a daemon that restarted with lower sequence numbers and starts over. A daemon with no stream is polled every second instead. It stops on Ctrl-C with exit `0`, and with exit `1` when the daemon rejects the key. `--once` prints what is held now and exits. `--json` prints each event as one line of JSON.

```text
2026-09-20T15:05:33.412887Z  guest_dns  guest-tap  vm=payment-prod-03  dst=10.20.0.2  name=updates.example.com  qtype=A
2026-09-20T15:05:33.412889Z  guest_tls  guest-tap  vm=payment-prod-03  dst=203.0.113.9  sni=api.example.com  tls=TLS1.3  alpn=h2
2026-09-20T15:05:33.412889Z  vmm_file_open  qemu-process  vm=payment-prod-03  path=/etc/shadow  comm=qemu-system-x86  pid=4121
```

Each line is time, kind, attribution, `vm=`, `dst=` (only when the event has a destination), then fields for the kind:

| Kind | Ends with |
|---|---|
| `guest_dns` | `name=` and `qtype=` |
| `guest_tls` | `sni=` and `tls=` (`-` when there is none), then `alpn=` and `ech` when the hello has them |
| `vmm_file_open` | `path=`, `comm=`, `pid=`, and `write` when the open asked to write |
| `vmm_syscall` | `syscall=`, `comm=`, `pid=`, then the call's arguments in words |

A tripwire event is about a call, not a peer, so it has no `dst=`. (An older `shukractl` printed `dst=<nil>` there.)

#### `export`

One JSON document: status, VMs, programs, the kvm, sched, block and net rows, and events. It is always JSON. It contains VM names, addresses and DNS names: treat it like the event list. Route: `GET /api/v1/export`.

### Security

#### `security <vm> [--json]`

Watchlist detections for one VM, and whether isolation can be enforced. Route: `GET /api/v1/security`.

```text
SECURITY  payment-prod-03  enforcement=tcx
  management allow list: 10.0.0.0/24
  high    payment-prod-03's QEMU process opened /etc/shadow  guest_attributed=false  attribution=qemu-process
```

`isolate is not enforced: <reason>` appears when it cannot be.

#### `isolate <vm> [--json]` and `release <vm> [--json]` (**admin**)

`isolate` asks the daemon to drop the VM's tap traffic except ARP, IPv6 neighbour discovery and the management allow list (`-isolate-allow`), and prints what actually happened. `release` lifts it. Routes: `POST /api/v1/isolate`, `POST /api/v1/release`.

```text
ISOLATE  batch-07
enforcement   tcx
applied       true
taps          vnet5
Traffic to and from vnet5 is dropped, except ARP, IPv6 neighbour discovery and 10.0.0.0/24. It stays enforced if shukrad stops or crashes. Lift it with `shukractl release`, or with the daemon down, `shukrad -detach-all`.
```

`applied` is `true` only after the kernel took the change on every tap. A refusal (no allow list, no such VM, no tap, no tap program) prints `applied false`, the reason, and `no datapath change — enforcement is not attached` when the enforcer is absent. **The exit status is still `0`**: see [Exit codes](#exit-codes).

#### `rules check <file> [--json]`

Validates a detection file offline with the daemon's own strict parser, so an edit can be tested before `systemctl reload shukra`. It contacts no daemon and needs no key. Unknown keys are an error, as the daemon treats them.

```text
$ shukractl rules check /etc/shukra/detections.yaml
ok: /etc/shukra/detections.yaml would be accepted
  suppress   5m0s
  ports      none
  exec_allow none
  thresholds none
  responses  none
```

It summarises `suppress`, `ports`, `exec_allow`, `thresholds` and `responses` (each response with what it will do: `propose`, `enforce` or `dry run`); it does not list `destinations`, `dns` or `tls` rules. A response that isolates on its own is called out: `<name> isolates a VM on its own, with no one to approve it: it answers <rules>`. A file the daemon would refuse prints the parser's error and exits `1`; with `--json` it first prints `{"ok": false, "error": "..."}` to stdout.

### Other

`shukractl version` (or `--version`) prints `shukractl <version>`. `shukractl help`, `-h`, `--help` or no arguments print the usage and exit `0`. An unknown command prints `unknown command "<x>" (try: shukractl --help)` and exits `1`.

## Past verdicts and incident bundles

`explain` normally weighs the last minute. `explain <vm> --at 2026-09-20T03:12:00Z` (or `--at -3h`, three hours ago) answers "why *was* it slow then" from the snapshots the daemon stores every 5 minutes under `-data-dir`: the verdict is the difference between the snapshot at or before that time and the one a window earlier. `--window` is then 5 minutes to 6 hours, default 15 minutes. It prints `at:` and `resolution:` so you can see how coarse it is. Where nothing is stored it says so and why (`no_history`) instead of guessing: no `-data-dir`, no snapshot at or before that time, the nearest one is more than ten minutes old (the daemon was not running), or not enough before it. A time in the future is an error.

`incident <vm> [--at ...]` puts that verdict together with the window's detections, what the flight recorder saw, the VM's isolate requests, the allow list and the programs into one document to attach to a ticket. It names VMs, addresses and DNS names, so `--out` writes it with mode `0600`.

History is bounded by size, not by time (see [architecture](architecture.md#persistence)): a day or two at ten VMs. Without `-data-dir` there is none, and `--at` says so. A walkthrough: [Investigate after the fact](tutorials/09-after-the-fact.md).

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SHUKRA_URL` | `http://127.0.0.1:30970` | Daemon base URL. A trailing `/` is dropped |
| `SHUKRA_API_KEY` | `~/.shukra/api-key` if unset | Bearer token. Never defaulted to the dev key |
| `SHUKRA_TLS_INSECURE` | on for `https` to a loopback host, otherwise off | `true` or `1` skips certificate verification, for a self-signed certificate |
| `SHUKRA_CA_FILE` | unset | A PEM file of CA certificates to trust, so a private CA works with verification on. Ignored when `SHUKRA_TLS_INSECURE` is on |
| `SHUKRA_SKIP_DOTENV` | unset | `1` does not read `~/.shukra/env` or `~/.shukra/api-key` |
| `SHUKRA_CLI_COLOR` | on for a terminal | `false` or `0` turns color off, any other value turns it on. Only the `help` screen is colored |
| `SHUKRA_CLI_NO_BANNER` | unset | Any value hides the banner. It is only printed by `help`, and only on a terminal or with color on |
| `NO_COLOR` | unset | Any value disables color ([no-color.org](https://no-color.org)). `TERM=dumb` does too |

## Exit codes

`0` on success and `1` on any error, which is printed to stderr as `error: <message>`. There are no other codes. An error is: the daemon unreachable or answering with an error status (the message carries `<METHOD> <path>: <body>`), a bad or missing argument, a `rules check` that fails, a file that cannot be written.

`doctor` exits `1` on a `fail`, and with `--strict` on a `warn` too, so it can gate a deploy; a clean or informational run exits `0`. It does so with `--json` as well.

**`isolate` and `release` exit `0` even when the daemon refuses them**, because the request itself succeeded. The answer is in the output: read `applied` (`--json` prints it as a boolean, and the board prints `applied false` with the reason). A script that isolates a VM must check `applied`, not the exit status.

## Scripting

Every board takes `--json`, and that form is the one to pipe. A VM that matches nothing is an empty result and exit `0`, not an error, so a script must check for an empty list.

```bash
# a health line for a cron job
shukractl doctor --strict >/dev/null || echo "shukra needs attention on $(hostname)"

# wait for a daemon that is starting, then go on
shukractl status --wait >/dev/null

# isolate, and fail unless it really happened
shukractl isolate payment-prod-03 --json | jq -e '.applied' >/dev/null || echo "not isolated"

# what is waiting for a decision
shukractl actions --json | jq -r '.actions[] | "\(.id) \(.vm) \(.rule)"'

# detections as they happen
shukractl watch --json | jq -c 'select(.kind == "detection")'

# validate a rules file in CI
shukractl rules check detections.yaml --json | jq -e '.ok' >/dev/null
```

For an unattended script use the read-only key wherever the command only reads, and keep the admin key for the few commands that change something.

## Install

```bash
make install
shukractl install-cli --prefix "$HOME/.local"
```
