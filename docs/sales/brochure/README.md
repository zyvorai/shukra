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
| `diagrams.py`, `svg.py` | the nine diagrams, drawn in code (`{{dia:name}}` in a page inserts one) |
| `build.py` | assembles the pages and prints the PDF; `_built.html` is its intermediate and is not committed |
| `zyvor-mark.svg` | the Zyvor Z used in the page header |
| `capture.sh` | drives the console in fixture mode with Playwright and writes `shots/<page>.png` |
| `shots/` | the captures the brochure uses; `capture.sh` writes every page, and only these are committed |

## Screenshots are fixtures

Every screenshot is rendered from `web/src/fixtures.ts`, not from a live host, and is captioned "Illustrative".
Do not caption one as a deployment. If the console changes, run `capture.sh` and look at each shot before
rebuilding. `capture.sh` needs `npm ci` in `web/` and Python 3 with Playwright and its Chromium.

## Where each claim comes from

Re-check these when the product changes. A number in the brochure that is not in this table should not be there.

| Claim | Source |
|---|---|
| 6 programs; 16 attach points (kvm 4, sched 4, block 2, net 3, tap 2, drops 1) | `bpf/*.bpf.c`, the `SEC("tracepoint/...")`, `SEC("kprobe/...")` and `SEC("tcx/...")` lines |
| Hooks, what each records, kernel needs (BTF and 5.8, drops 5.17, tap 6.6), `kvm_pio` absent on arm64 | `README.md` "What you get", `docs/architecture.md` "Kernel requirements", `docs/signals.md` |
| 1-in-64 retransmit samples; tap returns `TCX_NEXT`; pinned under `/sys/fs/bpf/shukra/tap` | `README.md`, `docs/tap.md`, `SECURITY.md` |
| 0 agents, nothing read from guests, the DNS-name exception (first question, at most 128 bytes, `-dns-events=false`) | `SECURITY.md` "What it reads", `docs/tap.md` |
| 14 console pages in 5 groups (Right-size is in Diagnostics) | `Page` type and `groups` in `web/src/components/Nav.tsx` |
| 28 routes: 3 operations, 25 under `/api/v1`, 3 of them POST (`isolate`, `release`, `baseline/forget`) | `internal/api/server.go` |
| 17 `shukractl` commands | `cmd/shukractl/commands.go` |
| Nine host-side causes and their wording; `no_host_cause`; `noisy_neighbour` at half of preempted time | `internal/state/verdict.go` (`noisyShare = 0.5`) |
| Explain windows (10 s to 5 min live; `--at` 5 min to 6 h, 15 min default); snapshots every 5 minutes; about a day or two at ten VMs | `README.md`, `docs/tutorials/09-after-the-fact.md`, `docs/architecture.md` |
| `/proc` rescan every 2 seconds | `docs/signals.md` "vCPU preemption" |
| vCPU preemption, who took the CPU, yields, names such as `kworker` | `docs/signals.md` "vCPU preemption" |
| Handshake outcomes and the 3 second "never answered" rule; the tap rig's 17 attempts (5, 6, 4, 2, one retransmit) | `docs/tap.md`, `docs/architecture.md` |
| Drop reasons and where to look; names read from the kernel's BTF | `docs/drops.md` |
| Isolation: allow list required, 6.6+, `applied`/`partial`, fails closed, `-detach-all`, not vhost-user or SR-IOV | `SECURITY.md` "Isolation", `docs/tap.md` |
| Six capabilities; data directory `0700`, files `0600`; events rate-limited to 200 per tap per second; DNS names cut at 253 bytes | `SECURITY.md` "Privilege" and "A hostile guest" |
| Right-size advice: halted / busy / preempted shares, the thresholds (80% halted and 20% busy with 2+ vCPUs; 50% busy and 10% preempted or a 2 ms wait; 95% halted with 1 vCPU), lower-bound caveat, the 30% "neither" gap, Intel-only exit names, the 3 minute and 20 second confidence limits, "not an action" | `docs/signals.md` "Right-sizing", `docs/tutorials/04-shukractl.md`, `internal/state/advice.go` |
| Learned baselines: `baselines:` section, 24 h learning, 20 alerts per VM per day, 2048 items per kind, 30 day aging, /24 and /64 and registrable-site grain, 63 built-in two-label suffixes, `baseline-cap` and `baseline-forgotten`, the example output | `docs/baselines.md`, `CHANGELOG.md` "Learned baselines" |
| Measured costs: `drops` about 255 ns per drop and 0.002% of a CPU; `sched` about 435 / 490 / 615 ns per switch and about 11 ms of CPU per second (under 0.1%), at about 60,000 switches a second on a 12-CPU Xeon with 10 VMs. No other program has a published cost | `docs/signals.md` (the sched "Cost" bullet and "Cost of `drops`"), `docs/drops.md` "Cost" |
| Read-only key cannot isolate; alert sinks (signed webhook, syslog, JSONL) | `SECURITY.md`, `README.md`, `docs/tutorials/07-alert-sinks.md` |
| State files, when written (including `baselines.json`), 16 MiB roll; recorder 4096 events per VM | `README.md` "Keep state across restarts", `docs/architecture.md` |
| 366 Go test functions, 45 console tests | `grep -rhE '^func Test' --include='*_test.go' . \| wc -l`, and `it(`/`test(` in `web/src` |
| CI, live guest (fluxvm) and release workflows; amd64 and arm64 packages | `.github/workflows/`, `README.md` "Continuous integration" |
| No tagged release yet | `CHANGELOG.md` |
| "Recently added" chips | the headings of `CHANGELOG.md` "Unreleased" |
| Apache-2.0, Copyright 2026 Zyvor | `LICENSE` |
| PacketWolf and Zeus OS as intended consumers, not in this repository | `README.md` |
| The `trace contention` and `explain --at` examples | copied from `docs/tutorials/09-after-the-fact.md` |
