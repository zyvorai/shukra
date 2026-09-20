# Doctor

`shukractl doctor` (and `GET /api/v1/doctor`, which is the same audit; the console does not show it yet) says what needs attention on this daemon and how to fix it. It is a **read of state, not a probe**: it changes nothing, touches no VM, and never contains an API key. The read-only key is enough to call it.

```bash
shukractl doctor              # only what needs attention, worst first, each with a fix
shukractl doctor --strict     # exit 1 on a warning too, so it can gate a deploy
shukractl doctor --json       # every check, including the ones that are fine
```

Each check has an `id`, a `status`, a `title`, an optional `detail` and an optional `fix`. The statuses, worst first:

| Status | Means | `doctor` exit status |
|---|---|---|
| `fail` | Something is unsafe or broken | `1` |
| `warn` | Something is wrong, or partly working | `0`, or `1` with `--strict` |
| `info` | A capability you may want that is not on | `0` |
| `ok` | Fine. Only in `--json` | `0` |

The text form prints everything that is not `ok` and ends with a count. A deploy on a lab host will list the dev key and plain HTTP; the deploy script says so without failing.

## The checks

### Who can call the API

| Id | Status | Fires when | Fix |
|---|---|---|---|
| `auth` | `fail` | `-no-auth` is set | Remove it and set `SHUKRA_API_KEY` |
| `auth` | `fail` | The key is the dev key `shukra` and the API listens on a non-loopback address | `SHUKRA_API_KEY=$(openssl rand -hex 16)` in `/etc/shukra/env` |
| `auth` | `warn` | The dev key on a loopback address (any local user knows it), or a key shorter than 16 characters | A real key of at least 16 characters |
| `transport` | `fail` / `warn` | Plain HTTP on a non-loopback address. `fail` when the key is the dev key or there is no auth, `warn` otherwise | `-tls-cert` and `-tls-key`, or listen on `127.0.0.1` |
| `readonly-key` | `info` | No `SHUKRA_READONLY_KEY`, so a scrape has to use the admin key, which can also isolate a VM | Set one and give it to Prometheus |

### The kernel and the programs

| Id | Status | Fires when | Fix |
|---|---|---|---|
| `kernel` | `warn` | Older than 5.8 (no `CAP_BPF`, so the service runs with full root capabilities) | Upgrade |
| `kernel` | `info` | Older than 6.6 (no TCX: the tap program, guest traffic and isolate are unavailable) | Upgrade to 6.6 or newer |
| `scan` | `warn` | The first `/proc` scan has not finished | Wait; the daemon reports ready after the first scan |
| `program-<name>` | `warn` | A program is only partly attached (`3/4 hooks`), or detached for a reason of its own | `shukractl programs` says why. A missing hook is usually a tracepoint this kernel or CPU does not have |
| `programs-detached` | `warn` | Several programs are detached for the **same** reason: one finding, not one per program | Usually the daemon was built without BPF: `make generate` and `-tags shukrabpf` |
| `program-tap` | `info` | The tap program has no VM tap to attach to yet | Nothing: it attaches when a VM with a tap starts |

### VMs Shukra cannot see, or cannot fully see

| Id | Status | Fires when | Fix |
|---|---|---|---|
| `blind-vms` | `warn` (`info` while the tap program is not attached) | A VM has **no known tap**: user-mode networking, or a libvirt VM whose tap fds the daemon cannot read. Their guest traffic is not seen and they cannot be isolated | For libvirt, the daemon needs `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`: use the shipped unit |
| `vm-tap-other-netns` | `warn` | A VM's tap is named but is **not in the host network namespace**, so there is nothing to attach to. FluxVM's per-VM netns is mapped to its host veth first, so this remains for a tap the scan could not map and for other runtimes | Put the tap in the host namespace. Shukra does not enter another namespace: the unit has no `CAP_SYS_ADMIN` |
| `vm-tap-untraced` | `info` | A VM's tap exists here but is not being traced. Normal for the moment after a VM starts; a problem if it stays | `shukractl programs` and the daemon log: the attach failed |

Both tap checks say nothing until the tap program is attached and has a source of what it traces. They name the first five VMs and count the rest.

### What is happening to a VM's traffic

These read the **last minute** of history, not the life of the daemon, and say which window they used. They say nothing for a program that is not measuring.

| Id | Status | Fires when | What to do |
|---|---|---|---|
| `vm-drops-not-shukra` | `warn` | The kernel dropped at least 5 packets on a VM's tap that Shukra's own isolation did not (`other` in [drops](drops.md)) | Another program is attached to the tap (Cilium, a dataplane, a `tc` filter): `bpftool net show dev <tap>` |
| `vm-nic-not-consumed` | `warn` | At least 5 packets were dropped because the tap's queue was full (`FULL_RING`) | The guest is stalled, has no working NIC driver, or is overloaded. Look at the VM |
| `vm-connects-failing` | `warn` | At least 10 of the VM's outbound TCP connections finished in the window and at least half were refused or never answered | Refused means nothing listens; never answered means something drops the SYN; many refusals to many ports looks like a scan. `shukractl trace tap --vm <vm>` has the counts |

[Find out why a VM's traffic is lost](tutorials/08-lost-traffic.md) walks from these three findings to a cause.

### Isolation, persistence, alerts and rules

| Id | Status | Fires when | Fix |
|---|---|---|---|
| `isolate` | `info` | Isolate is not enabled: no management allow list, or no tap program | `-isolate-allow <management CIDRs>` |
| `isolate` | `warn` | An allow list is set but the tap program is not attached, or there is no bpf filesystem to pin on, so isolation will not survive the daemon | `shukractl programs`; mount bpffs at `/sys/fs/bpf` |
| `persistence` | `warn` | No `-data-dir`: detections, isolation records and the flight recorder are lost on restart, and recorded isolations cannot be re-applied | `-data-dir /var/lib/shukra` (the shipped unit does) |
| `baselines` | `warn` | Learned baselines are on but there is no `-data-dir`, so learning starts over with every restart | `-data-dir /var/lib/shukra` |
| `baselines` | `info` / `ok` | Baselines are on: how many VMs are still learning (and when the last learning period ends), or that they are all reporting. Only present while the rules file has a `baselines:` section | Nothing |
| `alerts` | `info` | No sink is configured, so detections are only visible in the console, the CLI and `/metrics` | `-webhook-url`, `-syslog` or `-alert-file` |
| `rules` | `fail` | The detection file did not reload; the previous rules are still in force | `shukractl rules check <file>`, then `systemctl reload shukra` |
| `rules` | `info` | No `-watchlist`: only the built-in unexpected-exec check runs | `-watchlist /etc/shukra/detections.yaml` |

## What it does not check

It does not probe the network, try a VM, or read a guest. It cannot tell you a rule is a good rule, only that the file loaded. It does not check that Prometheus is scraping, or that a webhook endpoint is answering (the sink's own queue and errors are on `/metrics`, see [alert sinks](tutorials/07-alert-sinks.md)).

## Reading it from a script

```bash
shukractl doctor --strict >/dev/null || echo "shukra needs attention on $(hostname)"
shukractl doctor --json | jq -r '.checks[] | select(.status != "ok") | "\(.status) \(.id): \(.title)"'
```

The JSON is `{"worst": "...", "checks": [...]}`; see the [API reference](api.md).
