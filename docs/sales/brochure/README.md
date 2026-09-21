# Shukra product brochure (source)

The brochure is built from this directory, so it can be regenerated when the product changes.

```sh
python3 docs/sales/brochure/build.py            # writes Zyvor-Shukra-Product-Brochure.pdf here
python3 docs/sales/brochure/build.py --check    # also fails if any page's content overflows
docs/sales/brochure/capture.sh                  # re-shoot the console pages (see below)
```

Standard library only. The PDF is rendered by the installed Google Chrome in headless mode (`CHROME=/path`
selects another Chromium-based browser). The layout, the diagram helpers and the checker are the ones the Netra
brochure uses, so the two look alike.

| File | What |
|---|---|
| `pages_*.html` | the pages, one `<section class="page">` each (header, footer and page numbers are added by `build.py`) |
| `style.css` | the Zyvor look (orange `#ff5a15`, ink, warm paper), US letter |
| `diagrams.py`, `svg.py` | the twelve diagrams, drawn in code (`{{dia:name}}` in a page inserts one) |
| `build.py` | assembles the pages and prints the PDF; `_built.html` is its intermediate and is not committed |
| `zyvor-mark.svg` | the Zyvor Z used in the page header |
| `capture.sh` | drives the console in fixture mode with Playwright (it signs in with the fixture token, since the console keeps the token in memory only) and writes `shots/<page>.png` |
| `shots/` | the captures the brochure uses (overview, explain, contention, advice, drops, isolate, connections, policy, actions, and the three `readme-*` crops); `capture.sh` writes every page, and only these are committed |

## Screenshots are fixtures

Every screenshot is rendered from `web/src/fixtures.ts`, not from a live host, and is captioned "Illustrative".
Do not caption one as a deployment. If the console changes, run `capture.sh` and look at each shot before
rebuilding. `capture.sh` needs `npm ci` in `web/` and Python 3 with Playwright and its Chromium.

## Where each claim comes from

Re-check these when the product changes. A number in the brochure that is not in this table should not be there.

| Claim | Source |
|---|---|
| 22 pages in the PDF | `python3 docs/sales/brochure/build.py --check` (counts the `<section class="page">` blocks) |
| 8 programs; 35 attach points (kvm 4, sched 4, block 3, mem 3, net 3, vmm 15, drops 1, tap 2) | `bpf/*.bpf.c`, the `SEC("tracepoint/...")`, `SEC("kprobe/...")` and `SEC("tcx/...")` lines: `grep -cE '^SEC\("(tracepoint\|kprobe\|tcx)' bpf/*.bpf.c` per file |
| Hooks, what each records, kernel needs (BTF and 5.8 for kvm, sched, block, net and vmm; drops 5.17; tap, egress policy and isolation 6.6), `kvm_pio` absent on arm64 (`kvm` attaches 3 of 4) | `README.md` "The programs" and "Requirements", `docs/architecture.md` "Kernel requirements", `docs/signals.md` |
| `vmm`: 13 syscall tracepoints (`openat`, `openat2`, `open` and ten calls) plus fork and exit; watches QEMU processes and what they started at any depth (descent recorded at fork, three parents for one already running); 300 reported opens and calls a second per VMM; ten QEMU processes made none of the calls in thirty seconds; the built-in sensitive list (including `/etc/shukra` and `/var/lib/shukra`); path cleaned first; the three detections and their severities; the `vmm:` section (`paths`, `ignore`, `syscalls`, `severity`, `defaults`); `-vmm-tripwires=false` | `docs/vmm-tripwires.md` "What is watched", "What becomes a detection", "Changing what counts", `bpf/vmm.bpf.c` (`VMM_PER_SEC 300`, the `SEC` lines), `CHANGELOG.md` "VMM tripwires" |
| The tripwire is not a sandbox: path read when the call starts, symlink not followed, relative path from an exited process left as given, a VMM that does none of these is not seen, an open that fails still counts, isolation does not stop a process in the VMM's tree | `docs/vmm-tripwires.md` "What it does not see" and "From a tripwire to a response", `SECURITY.md` "A compromised VMM" |
| 1-in-64 retransmit samples; tap returns `TCX_NEXT`; pinned under `/sys/fs/bpf/shukra/tap` | `README.md`, `docs/tap.md`, `SECURITY.md` |
| 0 agents, nothing read from guests | `SECURITY.md` "What it reads, and what it never does" |
| The three exceptions to "no payloads": DNS names (first question of a plain UDP/53 query, at most 128 bytes copied, name cut at 253, `-dns-events=false`); TLS ClientHello (up to 1,504 bytes copied, decoded and discarded, `-tls-events=false` reads no TCP payload at all); VMM file names (path up to 256 bytes, never contents, `-vmm-tripwires=false`); and the host task `comm` the scheduler records | `SECURITY.md` "The exceptions to "no payloads"", `docs/tap.md` "DNS names" and "TLS server names", `README.md` "What it does not do" |
| TLS server names: the `guest_tls` fields (`sni`, `alpn` at most 8, `tls_version`, `ja3` only when the whole hello was seen, `ech`, `tls_truncated`); 100 events per tap per second on their own budget; ECH shows only the outer name; a truncated hello has no JA3; QUIC and HTTP/3 and the server's answer are not read; JA3 is the kind of client library, not who; `tls:` rules; baselines count the name as its site | `docs/tap.md` "TLS server names", `docs/baselines.md`, `bpf/tap.bpf.c` (`TLS_RAW 1504`, `TLS_PER_SEC 100`), the DNS and TLS tables on `web/src/fixtures.ts` |
| Egress policy: learn, audit (drops nothing, needs no allow list), enforce (needs `-isolate-allow`, `-data-dir` and `--confirm` 30 s to 24 h or `--permanent`); judges a TCP SYN and a UDP datagram that is neither multicast nor an answer; the management allow list is never judged; record saved before the kernel changes; a failed change is put back; the kernel keeps enforcing through a crash, restart and stop; an unconfirmed policy reverts even if the daemon was down; an orphan is flagged by `doctor`; `policy-*` detections and the low `egress-policy-audit` and medium `egress-policy-blocked`; networks only, not ports or names; a new tap gets its saved policy when the program attaches (the 2-second scan is the backstop); a resolver must be on the list | `docs/egress-policy.md`, `internal/policy/policy.go` (`MinConfirm`, `MaxConfirm`), `SECURITY.md` "Isolation and egress policy", `CHANGELOG.md` "Egress policy" |
| Responses: one action (isolate); off unless a `responses:` section exists; propose by default and a person approves; `enforce` must name its rules; `dry_run`; guardrails `never_isolate`, isolate must work, `max_per_hour` (default 3, 1 to 100, automatic only), `cooldown` (default 1 hour), `expire` (default 30 minutes), `release_after` (survives a restart), approval re-checks; every decision is an action recorded with `actions.jsonl` and `incidents/<id>.json` (mode 0600) and announced as `action-*`; a guest can get only itself isolated | `docs/responses.md`, `internal/detect/config.go` (`DefaultMaxActionsPerHour`, the 1 to 100 check), `SECURITY.md` "A hostile guest", `CHANGELOG.md` "Responses" |
| The incident bundle of a proposal: the verdict, the window's detections, up to 500 recorder events, isolate requests, the allow list and the programs, over the 15 minutes before the detection; nothing from the daemon's configuration | `docs/responses.md` "The flow", "Limits"; `docs/tutorials/09-after-the-fact.md` |
| 17 console pages in 5 groups: Overview 1, Investigate 3, Diagnostics 7 (Right-size and Memory among them), Network 2, Security 4 (Detections, Actions, Egress policy, Isolate) | `Page` type and `groups` in `web/src/components/Nav.tsx` |
| 38 routes: 3 operations (`/healthz`, `/readyz`, `/metrics`) and 35 under `/api/v1`, of which 27 are `GET` and 8 are `POST` (`isolate`, `release`, `baseline/forget`, `policy/apply`, `policy/confirm`, `policy/remove`, `actions/{id}/approve`, `actions/{id}/reject`); every `POST` needs the admin key (the read-only key is refused every method but `GET` and `HEAD`); `/healthz` and `/readyz` need no key, `/metrics` a bearer | `grep -c 'mux.HandleFunc' internal/api/server.go` (38) and the `auth` function in the same file |
| 21 `shukractl` commands: status, programs, trace, vms, explain, incident, advise, baseline, policy, actions, approve, reject, recorder, watch, export, security, isolate, release, rules, doctor, install-cli | the `switch args[0]` in `cmd/shukractl/commands.go` (`version` and `help` are handled before it) |
| Nine host-side causes and their wording; `no_host_cause`; `noisy_neighbour` at half of preempted time | `internal/state/verdict.go` (`noisyShare = 0.5`) |
| Explain windows (10 s to 5 min live; `--at` 5 min to 6 h, 15 min default); snapshots every 5 minutes; about a day or two at ten VMs | `README.md`, `docs/tutorials/09-after-the-fact.md`, `docs/architecture.md` |
| `/proc` rescan every 2 seconds | `docs/signals.md` "vCPU preemption" |
| vCPU preemption, who took the CPU, yields, names such as `kworker` | `docs/signals.md` "vCPU preemption" |
| Handshake outcomes and the 3 second "never answered" rule; the tap rig's 17 attempts (5, 6, 4, 2, one retransmit) | `docs/tap.md`, `docs/architecture.md` |
| Drop reasons and where to look; names read from the kernel's BTF | `docs/drops.md` |
| Isolation: allow list required, 6.6+, `applied`/`partial`, fails closed, `-detach-all`, not vhost-user or SR-IOV, ARP and IPv6 neighbour discovery always pass | `SECURITY.md` "Isolation and egress policy", `docs/tap.md` |
| Six capabilities; data directory `0700`, files `0600`; events rate-limited to 200 per tap per second for connects and for DNS, 100 for TLS; names cut at 253 bytes; the bounds (65,536 pending handshakes and UDP flows, 16,384 names seen, 2,048-event list in six classes, 4,096 recorder events per VM) | `SECURITY.md` "Privilege", "A hostile guest" and "Every table is bounded" |
| The trust table on the "Who can do what" page (host, admin key, read-only key, no key, guest, VMM, alert destinations) | `SECURITY.md` "Threat model" |
| The dev key and plain HTTP: the shipped unit listens on `127.0.0.1:30970`; plain HTTP off loopback is refused unless `-allow-insecure-http` is set; a daemon started without `SHUKRA_API_KEY` uses `shukra`; a fresh install generates a random key and an install over an older deploy keeps the key it finds; `doctor` fails the dev key on a non-loopback address | `SECURITY.md` "The dev key and plain HTTP: check your own install", `README.md` "Quick start" |
| Isolation, an enforcing policy and a response are refused without `-isolate-allow` (a `dry_run` response is still recorded) | `README.md` "Daemon flags", `docs/responses.md`, `docs/egress-policy.md` |
| Right-size advice: halted / busy / preempted shares, the thresholds (80% halted and 20% busy with 2+ vCPUs; 50% busy and 10% preempted or a 2 ms wait; 95% halted with 1 vCPU), lower-bound caveat, the 30% "neither" gap, Intel-only exit names, the 3 minute and 20 second confidence limits, "not an action" | `docs/signals.md` "Right-sizing", `docs/tutorials/04-shukractl.md`, `internal/state/advice.go` |
| Learned baselines: `baselines:` section, 24 h learning, 20 alerts per VM per day, 2048 items per kind, 30 day aging, /24 and /64 and registrable-site grain (sites come from DNS and TLS names), 63 built-in two-label suffixes, `baseline-cap` and `baseline-forgotten`, the example output | `docs/baselines.md`, `CHANGELOG.md` "Learned baselines" |
| Measured costs, each with the host it was taken on: `drops` about 255 ns per drop and 0.002% of a CPU; `sched` about 435 / 490 / 615 ns per switch and about 11 ms of CPU per second (under 0.1%), at about 60,000 switches a second on a 12-CPU Xeon with 10 VMs | `docs/signals.md` (the sched "Cost" bullet and "Cost of `drops`"), `docs/drops.md` "Cost" |
| Measured costs, `vmm`: about 183 ns per `openat` (fork about 860 ns, exit about 550 ns), 0.161% of one core at about 8,100 tracepoint hits a second, about 2% of a core at 100,000 opens a second, on an Intel Xeon E-2336 with Linux 6.8 | `docs/vmm-tripwires.md` "What it costs" |
| Measured costs, `tap`: TLS names add about 10 to 15 ns to a data segment, nothing to an ACK or UDP, about 60 to 85 ns to the hello segment, about 1 to 1.5% of a core at a million data segments a second; with no policy on a tap the egress check adds about 7 to 10 ns (76 to 78 ns before, 86 to 87 after), about 1% of a core at a million packets a second | `docs/tap.md` "What it costs", `docs/egress-policy.md` "Cost" |
| The daemon's own cost: about 55% of a core and 155 MB down to 5 to 9% and about 88 MB on a 12-core, 10-VM k3s and Cilium node; the recorder ring copied all 4,096 events per event; about 64,000 threads on the sched maps; batches of up to 2,048 entries instead of two calls per entry, over 200,000 calls per refresh; same output | `CHANGELOG.md` "The daemon's own cost on a busy host" |
| No other program has a published cost (`kvm`, `block`, `net`) | `docs/signals.md`, `README.md` "What it costs" |
| Read-only key cannot isolate or change a policy; alert sinks (signed webhook, syslog, JSONL) | `SECURITY.md`, `README.md`, `docs/tutorials/07-alert-sinks.md` |
| State files, when written (including `baselines.json`, `policies.json`, `actions.jsonl` and `incidents/`), 16 MiB roll; recorder 4096 events per VM | `README.md` "Keep state across restarts", `docs/architecture.md` |
| 545 Go test functions and 56 console tests in 12 files | `grep -rhE '^func Test' --include='*_test.go' . \| wc -l` prints 546, one of which is `TestMain`, which is not a test; `cd web && npx vitest run` |
| Go 1.27+ to build, Node 22 for the console | `go.mod`, `README.md` "Requirements" |
| CI, live guest (fluxvm) and release workflows; amd64 and arm64 packages; the live-guest test asks a real QEMU over QMP to open `/etc/shadow` and requires a critical `vmm-sensitive-open` for that VM, 58 of 58 checks on the reference hypervisor; an audit policy marks exactly what is outside its list on a real guest | `.github/workflows/`, `README.md` "Continuous integration", `docs/testing.md` "The live guest test", `CHANGELOG.md` "Build and tooling" |
| No tagged release yet | `CHANGELOG.md` |
| "Recently added" chips: the feature headings of `CHANGELOG.md` "Unreleased" (Build and tooling, Documentation refresh, API and CLI fixes, the two brochure entries and Console text are left out: they are not features) | the headings of `CHANGELOG.md` "Unreleased" |
| Apache-2.0, Copyright 2026 Zyvor | `LICENSE` |
| PacketWolf and Zeus OS as intended consumers, not in this repository | `README.md` |
| The `trace contention` and `explain --at` examples | copied from `docs/tutorials/09-after-the-fact.md` |
| The `vmm-sensitive-open` and `vmm-syscall` lines on the "Watching the VMM" page | copied from `docs/vmm-tripwires.md` "What becomes a detection" |
