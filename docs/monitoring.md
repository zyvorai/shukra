# Monitor the daemon

Back to the [README](../README.md).

| Endpoint | Auth | |
|---|---|---|
| `GET /healthz` | none | Process is up |
| `GET /readyz` | none | `200` after the first scan, `503` before. Body has attached and total programs |
| `GET /metrics` | bearer | Prometheus text. A VM with no measured counters has no series, not a zero |
| `GET /api/v1/status`, `/vms`, `/programs` | bearer | The board, the VMs and their taps and threads, and the programs |
| `GET /api/v1/doctor` | bearer, read-only key is enough | The same audit as `shukractl doctor`. It never contains a key |
| `GET /api/v1/trace/{kvm,sched,block,net,tap,drops,contention}` | bearer | Per-VM counters. `contention` is who took whose CPU across VMs. An empty list is `[]`, never `null` |
| `GET /api/v1/explain?vm=<name>&window=<dur>&at=<time>` | bearer | Ranked findings for one VM. `window` is 10s to 5m, or `0`; the default is the last minute. With `at` it is a past time, from stored snapshots (`window` is then 5m to 6h) |
| `GET /api/v1/advice?vm=<name>&window=<dur>` | bearer | Is each VM the right size: idle and busy shares, preemption, run-queue wait, and the advice with evidence. `window` is 1m to 5m (default 5m) |
| `GET /api/v1/incident?vm=<name>&at=<time>&window=<dur>` | bearer | One bundle about a VM around a moment: verdict, detections, recorder events, isolate requests, allow list |
| `GET /api/v1/recorder?vm=<name>&window=<dur>` | bearer | The bounded per-VM flight recorder: default 60 s, at most 4096 events |
| `GET /api/v1/detections?vm=<name>` | bearer | Rule hits, capped like events |
| `GET /api/v1/security?vm=<name>` | bearer | Detections, whether isolation is enforced (`tcx` or `not_attached`), the allow list, and whether isolation survives the daemon |
| `GET /api/v1/baseline?vm=<name>&items=1` | bearer | What each VM has learned as normal, and where its learning stands |
| `GET /api/v1/policy`, `/policy/proposal?vm=<name>` | bearer | Each VM's [egress policy](egress-policy.md) and what it has counted; what the baseline proposes |
| `GET /api/v1/actions?all=1`, `/actions/{id}/incident` | bearer | What [responses](responses.md) decided, and the bundle each was made on |
| `GET /api/v1/export` | bearer | One document (status, VMs, traces, events) for a bug report |
| `GET /api/v1/events?since=<seq>` | bearer | Events newer than `seq`. Every event carries a `seq` that only grows |
| `GET /api/v1/stream` | bearer | Server-sent events. Resume with `Last-Event-ID` or `?since=` |
| `GET /api/v1/isolations` | bearer | Audit trail of isolate and release requests, and whether each took effect |
| `POST /api/v1/isolate`, `/release` | admin key | Isolate or release a VM. Refused without a management allow list |
| `POST /api/v1/policy/apply`, `/policy/confirm`, `/policy/remove` | admin key | Put a VM under an egress policy, keep an enforcing one, lift one |
| `POST /api/v1/actions/{id}/approve`, `/reject` | admin key | Decide a proposed isolation |
| `POST /api/v1/baseline/forget` | admin key | Start one VM's learning over. Recorded as a detection |

The whole surface, with fields, is in the [API reference](api.md). Give Prometheus the **read-only** key (`SHUKRA_READONLY_KEY`): it can read everything and cannot isolate or change a policy. The API is plain HTTP unless you pass `-tls-cert` and `-tls-key`; `shukractl doctor` flags plain HTTP on a non-loopback address.


## Daemon flags

| Flag | Default | What it does |
|---|---|---|
| `-listen` | `127.0.0.1:30970` | API and console address |
| `-web` | `web/dist` | Console build to serve, if present |
| `-watchlist` | none | The rules file above |
| `-data-dir` | none | Keep detections, isolations, the recorder, policies, baselines and snapshots across restarts (below) |
| `-isolate-allow` | none | Comma-separated CIDRs an isolated VM can still reach. Without it, isolate, an enforcing policy and the action of any response are refused (a `dry_run` response is still recorded) |
| `-quarantine-uncovered` | `false` | Until an enforcing VM's saved policy is on a new tap, drop that tap except the management allow list. Off by default |
| `-dns-events` | `true` | Record the names a guest looks up. `false`: the program does not read DNS at all |
| `-tls-events` | `true` | Record the server names in a TLS ClientHello. `false`: the program does not read a TCP payload at all |
| `-vmm-tripwires` | `true` | Load the `vmm` program. `false`: it is not loaded |
| `-netlink-events` | `true` | Record host link, address, route and neighbor changes, and the detections made from them. `false`: those events and detections are not recorded; a link change still refreshes tap discovery |
| `-tls-cert`, `-tls-key` | none | Serve HTTPS (PEM). `SIGHUP` reloads the certificate. Required to listen off loopback unless `-allow-insecure-http` is set |
| `-allow-insecure-http` | `false` | Permit plain HTTP on a non-loopback address. The bearer key crosses the network in the clear |
| `-webhook-url`, `-syslog`, `-alert-file` | none | Alert sinks (webhook secret: `SHUKRA_WEBHOOK_SECRET`) |
| `-no-auth` | `false` | Serve the API without a key. `doctor` fails it |
| `-proc` | `/proc` | procfs root |
| `-detach-all` | | Remove every pinned tap program and its isolation, then exit. Works while the daemon is stopped |
| `-version` | | Print the version and exit |

The keys are environment variables, not flags: `SHUKRA_API_KEY` (admin) and `SHUKRA_READONLY_KEY`. The shipped unit puts them in `/etc/shukra/env`, mode `0600`, so `systemctl show` does not print them.

## Keep state across restarts

By default everything is in memory. `shukrad -data-dir /var/lib/shukra` (the systemd unit sets it) keeps:

| File | Written | Restored |
|---|---|---|
| `detections.jsonl` | on every detection | last 2048 |
| `isolations.jsonl` | on every isolate request | last 2048 |
| `recorder.json` | every minute and on clean shutdown | the per-VM flight recorder |
| `actions.jsonl`, `incidents/` | on every decision | what responses decided, and the incident bundle each was made on (empty until a response acts; the private directory is created either way) |
| `policies.json` | on every change | each VM's egress policy: its networks, its mode, and any timer waiting to be confirmed (only when a policy has been applied) |
| `baselines.json` | every minute, if it changed | what each VM has learned as normal (only when `baselines:` is on) |
| `snapshots.jsonl` | every 5 minutes | read on demand by `explain --at` and `incident`; not loaded into memory |

Counters and the event list are not saved: they are read from the kernel or rebuilt. After a crash the recorder can be up to a minute behind; detections and isolations are not. Each log rolls to `.1` at 16 MiB. The directory is `0700`, files `0600`, because they name your VMs and addresses.
