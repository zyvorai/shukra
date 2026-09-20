# shukractl

Walkthroughs: [tutorials](tutorials/README.md).

Operator CLI for Shukra. Same shape as Netra's `netractl`: banner, grouped help, human boards, `--json`. It does not load BPF.

```bash
shukractl --help
shukractl status
shukractl status --json
shukractl trace kvm --vm payment-prod-03
shukractl isolate payment-prod-03
```

`isolate <vm>` asks the daemon to drop the VM's tap traffic except the management allow list, and prints what actually happened: `applied` is true only after the kernel took the change. `release <vm>` lifts it. `trace tap` shows the guest's traffic per tap and what became of each connection; `trace drops` shows what the kernel dropped on each tap and whether it was Shukra. The [API reference](api.md) documents every field the `--json` forms print.

## Commands

| Command | What it does |
|---|---|
| `status [--json] [--wait]` | Daemon board: mode, programs, VMs, detections. `--wait` retries for up to two minutes while the daemon starts, which is what the deploy script uses |
| `doctor [--json] [--strict]` | Audit the daemon: exposure, what is attached, what it cannot see. Only findings that need attention are printed, worst first, each with a fix. Every check is listed in [doctor](doctor.md). `--strict` exits non-zero on a warning too |
| `programs` | Which observation programs are attached (`kvm`, `sched`, `block`, `net`, `drops`, `tap`), how many hooks, and why one is not |
| `trace list`, `trace kvm\|sched\|block\|net\|tap\|drops\|contention [--vm NAME]` | Per-VM counters from the daemon. `tap` adds the guest's connections and their outcomes; `drops` says what the kernel dropped on each tap and whether it was Shukra |
| `vms [--json]` | QEMU and FluxVM virtual machines found on the host |
| `explain <vm> [--window 5m\|lifetime] [--at TIME\|-90m]` | Why a VM looks slow, from the last minute by default: ranked host-side causes with evidence, and what Shukra cannot see |
| `incident <vm> [--at TIME\|-90m] [--window 15m] [--out FILE]` | Everything known about a VM around a moment, in one bundle for a ticket. Prints a summary; `--out FILE` writes the whole JSON to a private file (mode 0600) and `--json` prints it. See [past verdicts](#past-verdicts-and-incident-bundles) |
| `baseline [<vm>] [--items] [--forget]` | What each VM has learned as normal (networks, sites, inbound peers) and where its learning period stands; `--items` lists what one VM learned; `--forget` (admin key) starts one VM's learning over and is recorded as a detection. See [baselines](baselines.md) |
| `advise [--vm NAME] [--window 5m]` | Is each VM the right size? Over-provisioned (more vCPUs than it uses), starved (wants CPU and is preempted or made to wait), nearly idle, or fine, each with the numbers, how sure it is and its caveat. Advice for a person, never an action |
| `actions [--all] [--bundle <id> [--out FILE]]` | What responses decided: the proposals waiting for a person, and with `--all` everything held. `--bundle` prints the incident bundle an action was made on (`--out` writes it 0600). See [responses](responses.md) |
| `approve <id>`, `reject <id>` | Decide a proposal. `approve` isolates the VM (admin key); `reject` does nothing to it |
| `recorder <vm> [--window 60s]` | Replay the flight recorder |
| `watch [--json] [--once]` | Stream discrete events, resuming from the last one seen. A `vmm_file_open` line ends with `path=`, `comm=` and `pid=` (and `write`), a `vmm_syscall` line with `syscall=`, `comm=`, `pid=` and the call's arguments in words. A `guest_dns` line ends with `name=` and `qtype=`, a `guest_tls` line with `sni=` and `tls=` (`-` when there is none), and `alpn=` and `ech` when the hello has them |
| `export` | One JSON document: status, VMs, traces, events |
| `security <vm>` | Watchlist detections for one VM |
| `isolate <vm>`, `release <vm>` | Drop or restore the VM's tap traffic. Refused without a management allow list; says if it was not enforced |
| `rules check <file> [--json]` | Validate a detection file offline, before reloading. It lists each response with what it will do (propose, enforce, dry run) and warns about one that isolates on its own |
| `install-cli [--prefix DIR]` | Copy this binary onto PATH |

Every command that prints a board also takes `--json`.

## Past verdicts and incident bundles

`explain` normally weighs the last minute. `explain <vm> --at 2026-09-20T03:12:00Z` (or `--at -3h`, three hours ago) answers "why *was* it slow then" from the snapshots the daemon stores every 5 minutes under `-data-dir`: the verdict is the difference between the snapshot at or before that time and the one a window earlier (`--window`, 5 minutes to 6 hours, default 15 minutes). It prints `at:` and `resolution:` so you can see how coarse it is, and where nothing is stored it says so and why (`no_history`) instead of guessing.

`incident <vm> [--at ...]` puts that verdict together with the window's detections, what the flight recorder saw, the VM's isolate requests, the allow list and the programs into one document to attach to a ticket. It names VMs, addresses and DNS names, so `--out` writes it with mode 0600.

History is bounded by size, not by time (see [architecture](architecture.md#persistence)): about a day at ten VMs. Without `-data-dir` there is none, and `--at` says so.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SHUKRA_URL` | `http://127.0.0.1:30970` | Daemon base URL |
| `SHUKRA_API_KEY` | `~/.shukra/api-key` if unset | Bearer token |
| `SHUKRA_TLS_INSECURE` | auto on https loopback | Skip verify for a self-signed cert |
| `SHUKRA_CLI_COLOR` | on for a TTY | `false` disables color |
| `SHUKRA_CLI_NO_BANNER` | unset | Hide the banner |
| `NO_COLOR` | unset | Disable color |

`~/.shukra/env` is loaded when a variable is not already set. `SHUKRA_SKIP_DOTENV=1` skips that file.

## Install

```bash
make install
shukractl install-cli --prefix "$HOME/.local"
```

## Exit codes

`0` on success and `1` on an error: the daemon unreachable or returning an error, a bad argument, or a rules file that fails `rules check`. `doctor` exits `1` on a finding of `fail`, and with `--strict` on a `warn` too, so it can gate a deploy; a clean or informational run exits `0`.

**`isolate` and `release` exit `0` even when the daemon refuses them**, because the request itself succeeded. The answer is in the output: read `applied` (`--json` prints it as a boolean, and the board prints `applied false` with the reason). A script that isolates a VM must check `applied`, not the exit status.

## Scripting

Every board takes `--json`, and that form is the one to pipe. A missing VM is an empty result and exit `0`, not an error, so a script must check for an empty list. A quick health line for a cron job:

```bash
shukractl doctor --strict >/dev/null || echo "shukra needs attention on $(hostname)"
```
