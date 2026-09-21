# Doctor

`shukractl doctor` (and `GET /api/v1/doctor`, which is the same audit; the console does not show it yet) says what needs attention on this daemon and how to fix it. It is a **read of state, not a probe**: it changes nothing, touches no VM, and never contains an API key. The read-only key is enough to call it.

```bash
shukractl doctor              # only what needs attention, worst first, each with a fix
shukractl doctor --strict     # exit 1 on a warning too, so it can gate a deploy
shukractl doctor --json       # every check, including the ones that are fine
```

An abridged run against a daemon started with `-no-auth`:

```text
[FAIL] The API needs no key
       -no-auth is set, so anyone who can reach 0.0.0.0:30970 can read everything and call isolate.
       fix: Remove -no-auth and set SHUKRA_API_KEY.
[warn] 1 VMs are not reading their NIC
       payment-prod-03 (vnet4: 12) packets were dropped over 1m0s because the tap's queue was full.
       fix: The guest is stalled, has no working network driver, or is overloaded. Look at the VM itself.
[info] No read-only key
       A scrape or dashboard has to use the admin key, which can also isolate a VM.
       fix: Set SHUKRA_READONLY_KEY and give that to Prometheus.
...
9 checks passed, 6 need attention (worst: fail)
```

## Statuses and exit codes

Each check has an `id`, a `status`, a `title`, an optional `detail` (the specifics: which VMs, what number) and an optional `fix`. The statuses, worst first:

| Status | Means | `doctor` exit status |
|---|---|---|
| `fail` | Something is unsafe or broken | `1` |
| `warn` | Something is wrong, or partly working | `0`, or `1` with `--strict` |
| `info` | A capability you may want that is not on | `0` |
| `ok` | Fine. Only in `--json` | `0` |

The text form prints everything that is not `ok`, and ends with a count in which `info` counts as needing attention. `--json` prints `{"worst": "...", "checks": [...]}` with every check, and still exits `1` on a `fail`. `worst` is the worst status present. A check can have a different status depending on what it finds, and each `id` appears at most once (`program-<name>` is one id per program).

**Exactly four checks can be a `fail`.** Three are about who can reach the API or whether your rules are in force. The fourth is an enforcement record that was not saved.

| Check | `fail` when |
|---|---|
| [`auth`](#auth) | `-no-auth` is set, or the key is the dev key `shukra` and the API listens on a non-loopback address |
| [`transport`](#transport) | Plain HTTP on a non-loopback address **and** the key is the dev key or there is no auth |
| [`rules`](#rules) | The detection file failed to reload, so old rules are still in force |
| [`audit-persist`](#audit-persist) | Isolate or enforce succeeded and the audit line or the state file was not saved |

Everything else is at most a `warn`: something to fix, but not a reason to stop.

## Quick reference

| Id | Can be | About |
|---|---|---|
| [`auth`](#auth) | fail, warn, ok | The admin key |
| [`transport`](#transport) | fail, warn, ok | Plain HTTP or TLS |
| [`readonly-key`](#readonly-key) | info | No key for scrapes |
| [`kernel`](#kernel) | warn, info, ok | Kernel version |
| [`scan`](#scan) | warn | First scan not finished |
| [`program-<name>`](#program-name-and-programs-detached) | warn, info | One program partly or not attached |
| [`programs-detached`](#program-name-and-programs-detached) | warn | Several programs down for one reason |
| [`blind-vms`](#blind-vms) | warn, info | VMs with no known tap |
| [`vm-tap-other-netns`](#vm-tap-other-netns) | warn | Tap not in the host namespace |
| [`vm-tap-untraced`](#vm-tap-untraced) | info | Tap exists but is not traced |
| [`vm-drops-not-shukra`](#vm-drops-not-shukra) | warn | Something else drops a VM's packets |
| [`vm-nic-not-consumed`](#vm-nic-not-consumed) | warn | A guest is not reading its NIC |
| [`vm-connects-failing`](#vm-connects-failing) | warn | A guest's connections mostly fail |
| [`isolate`](#isolate) | info, warn, ok | Whether isolate works and survives the daemon |
| [`persistence`](#persistence) | warn, ok | Whether state survives a restart |
| [`audit-persist`](#audit-persist) | fail | An isolate or enforce that the audit did not save |
| [`alerts`](#alerts) | info, ok | Where detections go |
| [`rules`](#rules) | fail, info, ok | The detection file |
| [`baselines`](#baselines) | warn, info, ok | Learned baselines, only when on |
| [`responses`](#responses) | warn, ok | Responses, only when configured |
| [`egress-policy`](#egress-policy) | warn, ok | Egress policies, only when there are any |

## The checks

### Who can call the API

#### `auth`

The admin key (`SHUKRA_API_KEY`). One finding, the first that matches:

| Status | Fires when | Fix |
|---|---|---|
| `fail` | `-no-auth` is set: anyone who can reach the address can read everything and call isolate | Remove `-no-auth` and set `SHUKRA_API_KEY` |
| `fail` | The key is the well-known dev key `shukra` and the API listens on a non-loopback address | `SHUKRA_API_KEY=$(openssl rand -hex 16)` in `/etc/shukra/env`, then restart |
| `warn` | The dev key, on a loopback address: only this host can reach it, but any local user knows it | Set `SHUKRA_API_KEY` in `/etc/shukra/env` |
| `warn` | A key shorter than 16 characters | A real key of at least 16 characters: `openssl rand -hex 16` |
| `ok` | None of these | |

The daemon uses the dev key only when `SHUKRA_API_KEY` is unset, and says so at start. Loopback means `127.0.0.1` (any `127.x`), `::1` or `localhost`. `:30970` and `0.0.0.0:30970` are not loopback. The read-only key's strength is not checked. The check sees whether the key is the dev key and how long it is, never the key.

#### `transport`

What crosses the network.

| Status | Fires when | Fix |
|---|---|---|
| `ok` | The API is served over TLS (`-tls-cert` and `-tls-key`), or it is only reachable from this host | |
| `warn` | Plain HTTP on a non-loopback address: the bearer key crosses the network in the clear | `-tls-cert` and `-tls-key` (`SHUKRA_EXTRA_ARGS` in `/etc/shukra/env`), or listen on `127.0.0.1` |
| `fail` | The same, and the key is the dev key or `-no-auth` is set | The same, and fix `auth` |

The shipped unit listens on `127.0.0.1:30970` over plain HTTP, so a fresh deploy does not show this warning. It appears when you pass `-listen` for a non-loopback address together with `-allow-insecure-http` and no TLS. The daemon refuses to start in that shape without `-allow-insecure-http`. TLS termination in a proxy in front of a loopback listener is fine: the daemon sees a loopback address.

#### `readonly-key`

| Status | Fires when | Fix |
|---|---|---|
| `info` | No `SHUKRA_READONLY_KEY`: a scrape or dashboard has to use the admin key, which can also isolate a VM and change a policy | Set one and give that to Prometheus |

There is no `ok` form: the finding is absent once a read-only key is set.

### The kernel and the programs

#### `kernel`

Read from `/proc/sys/kernel/osrelease`. Nothing is reported if it cannot be read.

| Status | Fires when | Fix |
|---|---|---|
| `warn` | Older than 5.8: no `CAP_BPF`, so the service runs with full root capabilities | Upgrade if you can |
| `info` | 5.8 up to 6.6: no TCX, so the tap program cannot attach, and guest traffic and isolate are unavailable. Host probes still run | 6.6 or newer. Guest traffic requires TCX |
| `ok` | 6.6 or newer | |

#### `scan`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | The first `/proc` scan has not finished | Wait; the daemon reports ready after the first scan |

#### `program-<name>` and `programs-detached`

There are eight programs: `kvm`, `sched`, `block`, `mem`, `net`, `vmm`, `drops` and `tap`. `shukractl programs` says why each one is in the state it is in.

| Id | Status | Fires when | Fix |
|---|---|---|---|
| `program-<name>` | `warn` | The program is only partly attached (`3/4 hooks; <error>`). A missing hook is usually a tracepoint this kernel or CPU does not have; the program still works with the rest | Read the detail; nothing to do if the missing hook does not matter to you |
| `program-<name>` | `warn` | The program is detached, and for a reason no other program shares | `shukractl programs`; the detail is the reason |
| `programs-detached` | `warn` | Two or more programs are detached for the **same** reason: one finding that names them, not one per program | Usually the daemon was built without BPF: `make generate` and `-tags shukrabpf` |
| `program-tap` | `info` | The tap program has no VM tap to attach to yet | Nothing: it attaches when a VM with a tap starts |

Two things to know. The `tap` program is attached per VM interface, so on a host with no VM it is `detached` and that is `info`, not a warning. And turning a program off on purpose is a warning too: `-vmm-tripwires=false` leaves `vmm` detached with the reason `turned off with -vmm-tripwires=false`, so it shows as `program-vmm`, and `doctor --strict` will fail on it. The fix line says it was turned off on purpose and which flag to remove; a program that failed to attach is told to rebuild with BPF instead. The `-dns-events` and `-tls-events` switches do not change a program's state and are not reported.

### VMs Shukra cannot see, or cannot fully see

These are the tap coverage checks. A VM without a tap has no guest traffic, no drop counts and cannot be isolated or put under an egress policy.

#### `blind-vms`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | At least one VM in the scan has **no known tap**, and the tap program is attached | A VM on user-mode networking has no host interface, so there is no tap to find. For libvirt VMs the daemon needs `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` to read their tap file descriptors: use the shipped unit |
| `info` | The same, while the tap program is not attached (the VMs cannot be traced anyway) | |

The title reads `N of M VMs have no known tap` and the detail names the first five VMs and counts the rest.

#### `vm-tap-other-netns`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | A VM's tap is named but is **not in the host network namespace** the daemon runs in, so there is nothing to attach to | Put the tap in the host namespace. Shukra does not enter another namespace: the unit has no `CAP_SYS_ADMIN` |

FluxVM's default per-VM namespace is mapped to the host veth first, so this remains for a tap that the scan could not map and for other runtimes. See [FluxVM](tap.md#fluxvm).

#### `vm-tap-untraced`

| Status | Fires when | Fix |
|---|---|---|
| `info` | A VM's tap exists in this namespace but has no counters yet. Normal for the moment after a VM starts, since a new tap is picked up on the next scan; a problem if it stays | `shukractl programs` and the daemon log: the attach failed |

The two tap checks say nothing until the tap program is attached and has a source of what it traces.

### What is happening to a VM's traffic

These read roughly the **last minute** of history, not the life of the daemon, and say which window they used in the detail (`over 1m0s`). While there is less than 20 seconds of history they read since the daemon started and say `lifetime`. They say nothing at all for a program that is not measuring: `vm-drops-not-shukra` and `vm-nic-not-consumed` need the drops program attached, and `vm-connects-failing` needs the tap program attached. Each names the first five VMs and counts the rest.

#### `vm-drops-not-shukra`

| Status | Fires when | What to do |
|---|---|---|
| `warn` | The kernel dropped at least 5 packets on a VM's tap that neither Shukra's own isolation or egress policy did nor a full queue explains (`otherDrops` in [drops](drops.md)) | Something else attached to the tap is dropping them: Cilium, a network dataplane, a `tc` filter. `bpftool net show dev <tap>`, and [tap](tap.md#when-guests-cannot-reach-each-other) |

The detail gives the biggest reason: `payment-prod-03 (vnet4: OTHERHOST 9)`.

#### `vm-nic-not-consumed`

| Status | Fires when | What to do |
|---|---|---|
| `warn` | At least 5 packets were dropped because the tap's queue was full (`FULL_RING`, `guestNotReading` in [drops](drops.md)) | The guest is stalled, has no working NIC driver, or is overloaded. Look at the VM |

#### `vm-connects-failing`

| Status | Fires when | What to do |
|---|---|---|
| `warn` | At least 10 of the VM's outbound TCP connections finished in the window (accepted, refused or never answered) and at least half of those were refused or never answered | Refused means nothing listens on that port; never answered means something drops the SYN, such as blocked egress or an unreachable network; many refusals to different ports looks like a scan. `shukractl trace tap --vm <vm>` has the counts |

A connection that Shukra itself blocked (isolation, egress policy) is neither finished nor failed for this check.

[Find out why a VM's traffic is lost](tutorials/08-lost-traffic.md) walks from these three findings to a cause.

### Isolation, persistence, alerts and rules

#### `isolate`

| Status | Fires when | Fix |
|---|---|---|
| `info` | Isolate is not enabled: there is no management allow list (`-isolate-allow`), or the tap program is not loaded | `-isolate-allow <management CIDRs>` |
| `warn` | An allow list **is** set and isolate is still unavailable, for example because the tap program is not attached | `shukractl programs`: the tap program has to be attached |
| `warn` | Isolate works but will not survive the daemon: there is no bpf filesystem to pin on, so a restart reopens an isolated VM until it re-applies | Mount bpffs at `/sys/fs/bpf` |
| `ok` | Isolate is enabled and survives the daemon. The detail lists the management allow list | |

A build with no enforcer at all reports `info` (`Isolate is not available in this build`).

#### `persistence`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | No `-data-dir`: detections, isolation records and the flight recorder are lost on restart, recorded isolations cannot be re-applied, and there is no history for `explain --at` | `-data-dir /var/lib/shukra` (the shipped unit does) |
| `ok` | State is kept in the data directory | |

Without a data directory the daemon also refuses to enforce an egress policy.

#### `audit-persist`

| Status | Fires when | Fix |
|---|---|---|
| `fail` | An isolate or an enforcing policy took effect, and the audit line or the state file was not saved. The VM is contained. The record of who did it, or the record that would re-apply it, is missing. The counter is `shukra_audit_persist_failures_total` | Free space on the data directory. The check stays until the daemon restarts, and only after the disk accepts writes. An action left `executed_audit_degraded` was enforced |

The check is absent when nothing has failed.

#### `alerts`

| Status | Fires when | Fix |
|---|---|---|
| `info` | No sink is configured, so detections are only visible in the console, the CLI and `/metrics` | `-webhook-url`, `-syslog` or `-alert-file` |
| `ok` | Detections are delivered to the named sinks | |

It does not test that a sink delivers: the sink's own counters are `shukra_alert_sent_total`, `shukra_alert_failed_total` and `shukra_alert_dropped_total` on `/metrics`, see [alert sinks](tutorials/07-alert-sinks.md).

#### `rules`

| Status | Fires when | Fix |
|---|---|---|
| `fail` | The detection file did not reload after a `systemctl reload shukra` (`SIGHUP`); **the previous rules are still in force**, so the daemon runs on rules you may believe were replaced | `shukractl rules check <file>`, fix it, then `systemctl reload shukra` |
| `info` | No `-watchlist` is configured: only the built-in checks run | `-watchlist /etc/shukra/detections.yaml` |
| `ok` | Detection rules were loaded from the named file | |

A file that is wrong when the daemon **starts** stops the daemon, so `fail` appears after a bad reload, never at start. It clears when a reload succeeds.

### Learned baselines, responses and egress policy

These three appear only when the rules file turns the feature on (`baselines:`, `responses:`), or, for the egress policy, once a VM has one or the kernel applies one nobody recorded.

#### `baselines`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | Baselines are on but there is no `-data-dir`, so learning starts over with every restart and a daemon that restarts more often than the learning period never reports anything | `-data-dir /var/lib/shukra` |
| `info` | `N of M VMs are still learning their baseline`. Nothing is reported for a VM until its learning period ends; the detail says when the last one ends | Nothing |
| `ok` | Baselines are reporting what is new for every VM | |

See [baselines](baselines.md).

#### `responses`

| Status | Fires when | Fix |
|---|---|---|
| `warn` | At least one response proposes or enforces, but isolate is not enabled, so every action will be refused | `-isolate-allow <management CIDRs>`, or make the responses dry runs |
| `warn` | `N proposed isolations are waiting for a decision` (a proposal lapses if nobody decides) | `shukractl actions`, then `shukractl approve <id>` or `reject <id>` |
| `ok` | Responses are configured; the title says how many propose, enforce and dry-run | |

The first `warn` wins if both apply. Responses that are all dry runs never raise the first one. See [responses](responses.md).

#### `egress-policy`

One finding, the worst first:

| Status | Fires when | Fix |
|---|---|---|
| `warn` | A tap applies an egress policy that **nobody has a record of** (the record was lost, or something else set it), so the kernel is dropping or auditing what nothing can name and the daemon can never revert it | `shukractl policy remove <vm>` lifts it and puts the tap right |
| `warn` | The kernel is not doing what a policy says (a tap is in another mode) | It is put right on the daemon's next pass; if it stays, the tap program may have failed to take the list: read the daemon log |
| `warn` | `N enforcing egress policies are waiting to be confirmed`; unconfirmed, a policy is taken off again and the VM goes back to what it had | `shukractl policy confirm <vm>` keeps it, once the VM is seen to be working |
| `ok` | Policies are on: how many are audit and how many enforce, and in the detail how many new connections audit mode would have dropped | |

See [egress policy](egress-policy.md).

## What a fresh deploy shows

A host installed with the shipped unit and script has a generated admin key, a data directory, `-watchlist` pointing at `detections.yaml`, and no sinks or `-isolate-allow` until you add them. On a host with no VMs yet it typically shows `transport` `warn` (plain HTTP on `0.0.0.0`), and `info` for `readonly-key`, `alerts`, `isolate` and `program-tap`. The deploy script prints `doctor` at the end and does not fail on it. Set `SHUKRA_READONLY_KEY`, an alert sink, `-isolate-allow` and TLS as you need them, and re-run.

## What it does not check

It does not probe the network, try a VM, or read a guest. It cannot tell you a rule is a good rule, only that the file loaded. It does not check that Prometheus is scraping, that a webhook endpoint is answering, that a TLS certificate is close to expiry, or that the data directory has room. It says nothing about the `-dns-events`, `-tls-events`, `-netlink-events` and `-web` settings. Turning Netlink events off does not detach a program.

## Reading it from a script

```bash
shukractl doctor --strict >/dev/null || echo "shukra needs attention on $(hostname)"
shukractl doctor --json | jq -r '.checks[] | select(.status != "ok") | "\(.status) \(.id): \(.title)"'
curl -s -H "Authorization: Bearer $SHUKRA_READONLY_KEY" "$SHUKRA_URL/api/v1/doctor" | jq -r .worst
```

The JSON is `{"worst": "...", "checks": [...]}`; see the [API reference](api.md#get-apiv1doctor).
