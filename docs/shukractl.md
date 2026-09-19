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

`isolate <vm>` asks the daemon to drop the VM's tap traffic except the management allow list, and prints what actually happened: `applied` is true only after the kernel took the change. `release <vm>` lifts it. `trace tap` shows the guest's traffic per tap. `rules check <file>` validates a detection file offline. `doctor` audits the running daemon and exits non-zero on a failure (`--strict` also on a warning).

## Commands

| Command | What it does |
|---|---|
| `status [--json] [--wait]` | Daemon board: mode, programs, VMs, detections |
| `doctor [--json] [--strict]` | Audit the daemon: exposure, what is attached, what it cannot see. Only findings that need attention are printed, worst first, each with a fix. `--strict` exits non-zero on a warning too |
| `programs` | Which observation programs are attached, and why one is not |
| `trace list`, `trace kvm\|sched\|block\|net\|tap [--vm NAME]` | Per-VM counters from the daemon |
| `vms [--json]` | QEMU virtual machines found on the host |
| `explain <vm> [--window 5m\|lifetime]` | Why a VM looks slow, from the last minute by default |
| `recorder <vm> [--window 60s]` | Replay the flight recorder |
| `watch [--json] [--once]` | Stream discrete events, resuming from the last one seen |
| `export` | One JSON document: status, VMs, traces, events |
| `security <vm>` | Watchlist detections for one VM |
| `isolate <vm>`, `release <vm>` | Drop or restore the VM's tap traffic. Refused without a management allow list; says if it was not enforced |
| `rules check <file> [--json]` | Validate a detection file offline, before reloading |
| `install-cli [--prefix DIR]` | Copy this binary onto PATH |

Every command that prints a board also takes `--json`.

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
