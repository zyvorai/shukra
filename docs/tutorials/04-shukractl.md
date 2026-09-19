# Operator CLI

`shukractl` is the only thing you should need on a laptop once a hypervisor is running `shukrad`. It does not load BPF. It sends `Authorization: Bearer` and `X-Shukra-Actor: shukractl`.

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

`SHUKRA_SKIP_DOTENV=1` ignores that file. `NO_COLOR=1` or `SHUKRA_CLI_COLOR=false` turns color off. `SHUKRA_CLI_NO_BANNER=1` hides the banner. HTTPS to loopback skips verify unless you set `SHUKRA_TLS_INSECURE`.

Install onto your PATH:

```bash
shukractl install-cli --prefix "$HOME/.local"
```

## The board

```bash
shukractl status
shukractl status --json
shukractl programs
shukractl vms
shukractl vms --json
```

`status` is the one screen to trust first: product, version, mode `observe`, VM count, how many programs attached, detection count. The last line is the boundary, not a slogan: host traces only, guest tap attribution not attached.

`--json` is the form to pipe. Human boards are for a TTY.

## Traces

```bash
shukractl trace list
shukractl trace kvm --vm osboxes-debian
shukractl trace sched --vm osboxes-debian --json
shukractl trace block --vm osboxes-debian
shukractl trace net --vm osboxes-debian
```

`trace kvm` is exit, entry, MMIO, and PIO counters for that QEMU process. It is not a per-exit log.

`trace net` is `tcp_v4_connect` and a 1-in-64 sample of retransmits. The socket owner is QEMU. Do not brief it as guest egress. The JSON says `guest_attributed: false` and `attribution: "qemu-process"` when the PID joined a VM.

A VM name that does not match is an empty result, not a guessed one.

## Explain and the flight recorder

```bash
shukractl explain osboxes-debian
shukractl recorder osboxes-debian --window 60s
```

`explain` answers from evidence on hand. The missing list is part of the answer: guest tap, CPU steal, in-guest process. If those lines are present, Shukra is telling you it cannot see them.

`recorder` replays the bounded per-VM ring, default cap 4096, default window 60s. With `-data-dir` the ring is saved every minute and on clean shutdown and reloaded at start; without it the ring starts empty after a restart. Kinds you will actually see: `exec`, `tcp_connect`, `tcp_retransmit`, `block_slow` (at least 10ms), `sched_delay` (at least 20ms), `detection`, and process exit. Counters do not each become an event.

```bash
shukractl watch
shukractl watch --json --once
```

`watch` streams discrete events. `--once` prints what is buffered and returns.

## Security, without enforcement

```bash
shukractl security osboxes-debian
shukractl isolate osboxes-debian
```

`security` is the destination watchlist. A hit means the QEMU process connected to a CIDR in the YAML. See [the watchlist tutorial](06-watchlist.md).

`isolate` is a POST. The record is stored. The response is `applied: false` and `enforcement: "not_attached"`. The CLI prints that. If a runbook says the VM is now cut off, the runbook is wrong for this build.

Next: the same facts in the [console](05-console.md).
