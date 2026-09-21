# Changelog

Shukra 0.1.0 is tagged. This lists what has merged to `main`, newest first. Pushing a `v*` tag publishes a release (see [development](docs/development.md#releasing)).

## Unreleased

### Host network control-plane events

- **Link, address, route and neighbor changes are events.** The daemon listens to the kernel's routing Netlink groups and records `netlink_link`, `netlink_address`, `netlink_route`, `netlink_neighbor` and `netlink_error`, each `attribution: "host-netlink"`. A change on a VM's own tap names that VM; a host interface does not, and goes to the `_host` recorder. Naming the VM does not mean the guest made the change (`guest_attributed` stays false). They share the host-network share of the event list with `tcp_connect`. See [Netlink control-plane events](docs/netlink.md).
- **A change that can cut a VM off is a detection, with nothing to configure.** `tap-link-deleted`, `tap-link-down` and `tap-master-changed` are high; `tap-mtu-changed` and `tap-address-removed` are medium; they fire only for an interface the scan names as a VM tap. `default-route-removed` (high) and `neighbor-failed` (medium) fire for any interface. `netlink-overrun` (high) is a lost Netlink message. The first observation of a tap is not reported as an MTU or master change. A host interface going down is recorded and is not a detection. The detection keeps `host-netlink`. `-netlink-events=false` stops the events and these detections.
- **Link notifications still refresh tap discovery**, debounced by 50 ms, including when `-netlink-events=false` has turned the events off. The socket accepts kernel messages only (sender PID zero), uses a 1 MiB receive buffer, and reports `ENOBUFS` as `netlink_error`.
- Checked on the reference hypervisor (Linux 6.8): the classifier tests pass. A dummy interface that no VM owns produced `neighbor-failed` and, from a route in table 220, `default-route-removed`, both `host-netlink` and not guest-attributed. It did not raise a tap detection, and it did not change the host's real default route. The ten VMs and eight programs stayed attached.

## 0.1.0

### Guest traffic is TCX on Linux 6.6 and newer

- **There is no classic tc datapath.** The tap program attaches with TCX only. A kernel older than 6.6 keeps the host probes and reports `tap` detached (`TCX needs Linux 6.6 or newer`). That is a failed attach, not a supported mode. `shukractl doctor` says the same thing. See [guest traffic](docs/tap.md) and [v0.1.0](docs/releases/v0.1.0.md).
- **A new tap is attached from netlink**, then its saved egress policy is written before the daemon reports that tap as covered. The two-second scan remains the backstop. An enforcing VM with a live tap and no program raises `tap-uncovered`. `-quarantine-uncovered` is off by default.
- **The container command is the listen address.** The image entrypoint is `shukrad`. The default command listens on `127.0.0.1:30970`, so `docker run -p` does not publish the API until that command is replaced, with TLS or with `-allow-insecure-http` behind a TLS proxy. systemd on the hypervisor is still the install. See [Deploy a hypervisor](docs/tutorials/03-deploy.md#container).

### Release hardening

- **The unit listens on loopback.** Plain HTTP on any other address is refused unless `-allow-insecure-http` is set. `-no-auth` off loopback is refused even then. The console login is the API token only.
- **An audit write that fails after an isolation is visible.** The action is `executed_audit_degraded`, `shukra_audit_persist_failures_total` counts it, and `doctor` fails. Action lines and incident bundles are fsynced, including the parent directory.
- **Mutating calls record who asked** as a hashed key id (`admin:` or `readonly:` and six hex characters), plus an optional client label, the source address, the request id, the role and the operation. The key itself is not stored.
- **CI** runs the race detector, `go vet`, `staticcheck`, `govulncheck` at `v1.8.0`, short fuzz targets, coverage as an artifact, `npm audit`, and an arm64 job. Release artifacts can include a CycloneDX SBOM and, when `COSIGN_PRIVATE_KEY` is set, cosign signatures. `scripts/verify-release.sh` checks a downloaded directory.

### Memory pressure and block queue time

- **Direct reclaim and OOM kills are measured on the host.** The `mem` program times `mm_vmscan_direct_reclaim` in the VMM process and records `oom/mark_victim`. `shukractl trace memory` and `shukra_reclaim_*` / `shukra_oom_kills_total` are that. It is not the guest's own memory.
- **Block queue time is separate from device time.** `block_rq_insert` to `block_rq_issue` is queue time (`queueReadP99Ns`, `shukra_block_queue_seconds`). `block_rq_issue` to `block_rq_complete` is service time (the latency histogram). A completion with a non-zero status counts in `readErrors` / `writeErrors`.

### Build and tooling

- **Go 1.27.** `go.mod` and the three workflows build with Go 1.27 (from 1.25). No source change was needed; `go vet`, `go test ./...`, the linux builds and the tagged BPF type-check are clean.
- **Console dev tooling:** `vite` 7.3.5 and `vitest` 4.1.11, which clear every open Dependabot alert (all were in dev tooling, none in the built console or the Go binaries); `npm audit` reports none.
- **The live-guest test makes a real QEMU trip the wire.** It asks the disposable guest's own QEMU, over its own QMP socket, to open `/etc/shadow` (a read-only file node, removed straight after) and requires a critical `vmm-sensitive-open` detection naming that VM and attributed to the VMM, not the guest. Run on the reference hypervisor: 58 of 58 checks.

### Documentation refresh

- Every guide was re-checked against the code and rewritten where it had drifted: seven programs and 31 attach points (the architecture and README still said six), the persistence table for every file under `-data-dir`, the trust boundaries (what a guest or a taken-over VMM controls and how each table is bounded), a complete API and metrics reference, every `shukractl` command with real output, all 20 `doctor` checks with the condition that fires each, and the exceptions to "no payloads" named wherever it is claimed.
- **The product brochure is 22 pages** (from 16) and the social card says seven programs. New pages: what it costs (measured), which sites a VM talks to (DNS and TLS names), watching the VMM, where a VM may connect (egress policy), acting on a detection safely, and who can do what. Every count and claim has a row in the claims table, recounted from the code: 7 programs, 31 attach points, 16 console pages, 37 routes (8 that change state), 21 `shukractl` commands, 545 Go test functions, 56 console tests. `capture.sh` works again (the console keeps its token in memory, so it signs in through the form).
- Two new tutorials: [an egress policy, from learning to enforcing](docs/tutorials/10-egress-policy.md) and [watching the VMM itself](docs/tutorials/11-vmm-tripwires.md).

### Egress policy: which networks a VM may connect to

- **`shukractl policy`** turns a VM's learned baseline into a list of networks it may start connections to, tries it in **audit** mode (nothing is dropped; what would be is counted and reported), and only then **enforces** it. `learn` proposes a list and shows how it differs from what the VM has; `apply` puts a VM under one; `confirm` keeps an enforcing policy; `remove` lifts one. `GET /api/v1/policy`, `.../proposal`, and admin-only `apply`, `confirm` and `remove`. See [egress policy](docs/egress-policy.md).
- **Built so a wrong policy cannot quietly cut a VM off.** Audit needs nothing; enforcing needs the management allow list (which no policy can take away), a `-data-dir`, and either `--confirm <duration>`, after which the VM goes back to what it had unless a person confirms, or `--permanent`. The record is saved before the kernel is changed, a change that fails is put back, the kernel keeps enforcing without the daemon (a crash, a restart and a graceful stop all leave an enforcing tap enforcing), an unconfirmed policy reverts even if the daemon was down when its time ran out, and a tap enforcing a policy nobody recorded is an orphan that the doctor flags and `policy remove` puts right.
- **It judges what the guest starts, not what it answers:** a TCP SYN, and a UDP datagram that is not multicast and not an answer to one that came in. A server keeps working under enforcement; ICMP, established connections, multicast and broadcast are not judged.
- A connection outside a policy is a `guest_connect` or `guest_flow` with `policy: "audit"` or `"enforce"`, a low `egress-policy-audit` or medium `egress-policy-blocked` detection, and counters on `/metrics` (`shukra_egress_*`). Drops are Shukra's own, so the drops accounting does not blame someone else for them. Applying, confirming, reverting and removing raise `policy-*` detections.
- **The kernel side is one new pair of maps for the lists, one for counters and one flow table; the mode is the second byte of `tap_policy`'s value, which always had seven spare, so no existing map changed.** With no policy on a tap the program does one extra read and compare per packet: about 7 to 10 ns (a data segment 76 to 78 ns before, 86 to 87 ns after) on the reference host.
- **`scripts/test-tap-progrun.sh`** checks every rule of the policy packet by packet on a real kernel, with `BPF_PROG_TEST_RUN` on a private copy of the program (no namespace, veth or VM, safe on a production host); CI runs it first. Section 15 of the rig covers the daemon: audit, enforce, the floor, a server still working, the timer, `kill -9`, a lost record, and isolation together with a policy. The live-guest test puts an audit policy on a real KVM guest and takes it off again.
### VMM tripwires

- **A new `vmm` program** watches every QEMU process, and what it started (at any depth: descent is recorded at fork, so a shell that backgrounds a job and exits has not shaken it off), for the files it opens (`vmm_file_open`) and the calls a VMM never makes (`vmm_syscall`): `ptrace`, `process_vm_writev` and `readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load` and `kexec_file_load`. A steady-state VMM does none of them (ten QEMU processes made none in thirty seconds on the reference host), so any one is a detection, with nothing to configure: `vmm-sensitive-open` (critical), `vmm-syscall` (critical or high by call) and `vmm-flood` (a VMM that reports more than 300 calls a second). See [VMM tripwires](docs/vmm-tripwires.md).
- **What is sensitive is decided in the daemon, so it can change without a new program.** A built-in list (`/etc/shadow`, sudoers, ssh keys, `/proc/*/mem`, `/proc/kcore`, the docker and containerd sockets, `/etc/shukra` and `/var/lib/shukra`, k3s server files) and a `vmm:` section of the rules file to add `paths`, `ignore` some (a VM image under a directory the list names), narrow `syscalls`, set `severity` or drop the `defaults`. A path is cleaned before it is judged (`/etc/../etc//shadow`), and a relative one is resolved from `/proc` while the process is still there.
- **It is a tripwire and not a sandbox**, and the guide says where it stops: the path is read when the call starts, a symlink is not followed, a process that has exited leaves a relative path as given, a process already running before its VMM was seen is found only through three parents, and a VMM that does none of these is not seen.
- **Cost, measured on the reference host:** about 183 ns per open (the tracepoints fire for every process, so each first finds out whether the caller is a VMM or descends from one), plus a fork and an exit hook that keep the record of descent, 0.161% of one core in all at about 8,100 hits a second, inside the 0.2% the design allowed. It scales with the host's open rate: about 2% of a core at 100,000 a second. `shukrad -vmm-tripwires=false` does not load the program.
- The kernel program was mutation-checked (fifteen breakages of the C, each caught by `TestKernelIntegrationVMMTripwires`, which loads the real program and runs in CI and safely on a production host), and section 16 of the rig and the live-guest test cover the daemon and a real QEMU.

### The daemon's own cost on a busy host

Found by profiling the daemon on a production hypervisor (12 cores, 10 VMs, a k3s and Cilium node): it was using about **55% of a core** and 155 MB, nearly all of it garbage collection. It now uses **5 to 9% of a core** and about 88 MB, with the same output.

- **The flight recorder is a real ring.** Once a VM's ring was full, every event copied all 4096 events into a new slice, over a megabyte of pointers for the garbage collector to scan, per event. Adding an event to a full ring now allocates nothing (a test asserts it). Order, the time window, snapshots and the nil-when-empty contract are unchanged.
- **Scheduler counters of threads no VM owns are summed as they are read.** The sched maps hold every thread that has run on the host (about 64,000 on that node), and each 2-second refresh allocated a `Counters` for each of them only for `aggregate.group` to add them into the `_host` row. They are now added into one slot as they are read. A test feeds the same readings through both paths and checks that the scheduler rows and per-thread rows the API serves are identical.
- **The large maps are read in batches**, one system call for up to 2048 entries instead of two per entry (over 200,000 system calls per refresh on that node). A kernel or map that cannot batch falls back to the old walk.
- **`scripts/bench-tap.sh`** measures what the tap program costs per packet on the kernel it runs on, using `BPF_PROG_TEST_RUN` on a private copy that has its own maps and is attached to nothing, so it is safe on a production host. It takes two objects to show what a change costs. The measured cost of TLS server names is in [docs/tap.md](docs/tap.md#what-it-costs).

### TLS server names

- **`guest_tls` events:** the server name (SNI) in the TLS ClientHello a guest sends, seen on its tap, with the protocols it offered (`alpn`), the highest version (`tls_version`), a JA3 fingerprint (only when the whole hello was seen), `ech` when Encrypted Client Hello is in use, and `tls_truncated` when the hello did not fit the copy. IPv4 and IPv6. One event per connection, with its own budget of 100 a second per tap, so a guest cannot flood the ring or starve the connect events. It names a site even when DNS was not used, and a guest that reaches a resolver over HTTPS is still seen going there. See [TLS server names](docs/tap.md#tls-server-names).
- The tap program copies up to 1504 bytes of a TCP payload only when it starts a handshake record that carries a ClientHello (checked on several bytes, so encrypted data is not taken for one), and the daemon decodes it and throws the bytes away. `shukrad -tls-events=false` makes the program read no TCP payload at all; the switch is a pinned map that the daemon sets on every start. The README, SECURITY and architecture no longer say "no payloads" without naming this exception.
- **`tls:` rules** in the rules file (suffix, exact or contains, like `dns:`), which do not judge each other's names; learned baselines count a server name as the site it names; `shukractl watch` shows `sni=`; the console's Connections page has a table of them, searchable by name, protocol and fingerprint.
- New pinned maps `tap_tls` and `tls_cfg` and unpinned `tls_flows` and `tls_rate`; no existing map changed. A tap program from before this change still runs and just has no TLS names.

### API and CLI fixes found by auditing the docs against the code

- **Empty lists are `[]` in every API answer.** `isolations`, `detections`, the sched `threads`, the `security` board's `detections` and `allowList`, and the export's `vms`, `programs`, `kvm`, `sched`, `block`, `net` and `events` came back `null` when empty, against the rule the rest of the API keeps. A test now asks every route with nothing known and again with one silent VM, and fails on any `null`. `shukractl rules check --json` does the same for `ports`, `execAllow` and `thresholds`.
- **`shukractl recorder` and `security` escape the VM name** (and the recorder's window). A name with a space, `&` or `#` used to make a request the daemon refused with 400 or asked for a different VM.
- **`shukractl actions --all`** no longer says an action "releases itself at 0001-01-01" when it never had a release timer, and **`shukractl watch`** no longer prints `dst=<nil>` for an event that has no destination (every VMM tripwire event).
- **`shukractl doctor`** no longer tells an operator who turned a program off (`-vmm-tripwires=false`) to rebuild with BPF; it says it was turned off on purpose and which flag to remove.

### Responses: acting on a detection, safely

- A `responses:` section in the rules file lets a detection propose isolating a VM, which a person approves (`shukractl approve`, the Actions page), or, with `mode: enforce` and named rules only, do it on its own. Guardrails apply to every response: `never_isolate`, isolate must be enabled, an hourly cap on automatic isolations, a per-VM cooldown, proposal expiry and a timed `release_after` that survives a restart. `dry_run` tries one out and changes nothing. Off unless configured. See [responses](docs/responses.md).
- Every decision is an action with the incident bundle it was made on, recorded in `actions.jsonl` and announced as an `action-*` detection (so a webhook can page whoever must approve).
- `shukractl actions`, `approve`, `reject`; `GET /api/v1/actions`, approve and reject (admin key only) and `.../incident`; `shukra_actions*` series; a `responses` doctor check; an Actions page.

### Brochure refresh

- The product brochure is now **16 pages**. New pages cover the right-sizing advisor (what `shukractl advise` reads, the lower-bound and "neither" caveats, Intel-only exit names, advice and never an action) and learned baselines (the learning period, the three kinds of first sighting, how they are bounded against a guest, and forgetting). The hypervisor page gains a table of the **measured costs** that the docs publish (`drops`, `sched`), and the "what it reads" page says what a guest can and cannot do to a baseline.
- Numbers brought up to date with `main`: 14 console pages, 28 routes (three that change state), 17 `shukractl` commands, 366 Go tests and 45 console tests. The claims table has the new rows.
- The Right-size page is in the console screenshots (`capture.sh` now shoots it). README: the at-a-glance line and the brochure row.

### Learned baselines

- A `baselines:` section in the rules file turns on learning what is normal for each VM: the networks it talks to (/24, /64), the sites it looks up (registrable names) and the networks that connect in. After a per-VM learning period (24h by default, from the first time the VM is seen) the first sighting of anything new is reported once as `new-destination`, `new-dns-suffix` or `new-inbound-peer`, guest-attributed. Off unless the section is present. See [learned baselines](docs/baselines.md).
- Bounded against a guest: fixed-size sets, a daily cap on alerts per VM with a single `baseline-cap` detection, aging of unseen items.
- `shukractl baseline [<vm>] [--items] [--forget]`, `GET /api/v1/baseline`, `POST /api/v1/baseline/forget` (admin only, recorded as a detection), `shukra_baseline_*` series, a `baselines` doctor check, and `baselines.json` under `-data-dir`.

### Right-sizing advisor

- `shukractl advise` and `GET /api/v1/advice`: per VM the share of the window its vCPUs were halted, busy and preempted, and advice with evidence and confidence: `overprovisioned` (with a size that leaves twice the headroom it used), `starved` (reduce what it competes with before adding vCPUs), `nearly_idle`, `no_change`, `not_enough_data` and `idle_unavailable`. Idleness is halt time (a lower bound) and only named on Intel hosts; elsewhere nothing about over-provisioning is claimed.
- A **Right-size** page in the console.

### Product brochure, and a social image that can be regenerated

- **A 14-page product brochure** (`docs/sales/brochure/`, PDF and source): what Shukra is and where its programs attach, a slow VM followed from the first symptom (Explain, who took the CPU, a past time, lost traffic and isolation), what it reads and never does, the console, rules and state, deploy and testing, and a buying checklist. Built by `build.py` (standard library plus headless Chrome) with a claims-to-source table, so a number that is not in a source file does not ship.
- The console fixtures (`web/src/fixtures.ts`) now describe a host where all six programs are attached, with tap handshake outcomes, kernel drops, guest events, contention pairs, an isolation and four Explain findings, so the screenshots in the brochure and README show the product working. Fixture mode is still not live data, and every screenshot is captioned as such. `capture.sh` re-shoots the pages.
- **The social image is generated.** `docs/social/build-social-card.sh` renders `shukra-social-card.html` to a real 1600x900 PNG and writes `docs/shukra-social.png` and `web/public/og.png`, which stay byte-identical. The old file was a JPEG with a `.png` name and no source.
- README: badges, an at-a-glance line, a screenshot strip and a link to the brochure; the API table now lists `recorder`, `detections`, `security` and `export`.

### Noisy-neighbour map

- `shukractl trace contention` and `GET /api/v1/trace/contention`: who took whose vCPU time across VMs, how much of each VM's preemption one other VM accounts for, the VM's own threads and host tasks, and what each culprit VM was doing over the same window. A **Contention** page in the console.
- New Explain cause `noisy_neighbour` when one other VM accounts for at least half of a VM's preempted time. `cpu_preempted` stays beside it.
- No new Prometheus series: `shukra_sched_vcpu_preempted_by_seconds_total{by="vm:<name>"}` already carries the pairs.

### Explain a past time, and incident bundles

- With `-data-dir` the daemon stores a coarse snapshot every 5 minutes (`snapshots.jsonl`, read on demand, bounded by size). `shukractl explain <vm> --at TIME|-3h [--window 15m]` answers "why *was* it slow then" from the two snapshots around that time, says how coarse that is, and says why when nothing is stored (`no_history`) instead of guessing.
- `shukractl incident <vm> [--at ...] [--out FILE]` and `GET /api/v1/incident`: one bundle for a ticket (verdict, the window's detections, recorder events, isolate requests, allow list, programs). It holds nothing from the daemon's configuration except the allow list, and `--out` writes it with mode 0600.
- The Explain page has an **At** field and a **Download incident bundle** button.
- Fixed: a live Explain with no recorder events returned `"events": null` instead of `[]`.

### Events: a share for each kind

- The daemon's 2048-event list is no longer one oldest-first queue. Each kind of event has a share that a flood of another kind cannot take (guest 512, host network 512, and 256 each for notable, process, latency and other), so a guest's DNS name or an inbound connect is no longer evicted within minutes by a k3s node's connects or slow-block samples. A kind may still use every slot while nothing else wants them. See [architecture](docs/architecture.md#state-windows-and-history).

### Console: filtering the connection tables

- Host connections, guest connections and DNS names are newest first, show 50 rows with the total (`Host connections (247)`) and a "show 50 more" button, and can be narrowed by VM (or "host processes (no VM)") and by a search on address, port, name or kind. An empty result says whether it is the filter or nothing has happened.

### Console text and defaults

- The VM field on Explain, Flight recorder and Isolate opens on the first VM the daemon actually knows and suggests the others, instead of a fixture name (`payment-prod-03`) that does not exist on the host.
- The sign-in page names the daemon you are talking to, not `127.0.0.1:30970`.
- Text that had fallen behind the product: the Overview said network events stay on the QEMU process "until tap/TCX ships" and that guest tap flows are not measured; the Host connections banner said tap attribution is not attached; the Isolate page said isolate "would only record an audit row". The Overview now says a guest is not measured only when it has fetched the programs and the tap is off.
- Table titles no longer say "Ns" for durations that are shown with a unit (1.2 ms); the Scheduler and VMs heroes mention preemption and FluxVM.

### vCPU preemption: who took the CPU

- **The `sched` program now records preemption:** when a QEMU thread leaves a CPU while still runnable, who took the CPU is remembered, and the wait is charged when the thread runs again. Reported for vCPU threads only, by VM (`vm:<name>`) or host command name. See [vCPU preemption](docs/signals.md#vcpu-preemption).
- `trace sched` (`vcpuPreemptedNs`, `vcpuPreemptions`, `topPreemptors`), the Scheduler page, `shukra_sched_vcpu_preempted_seconds_total` and `shukra_sched_vcpu_preempted_by_seconds_total`.
- New Explain cause `cpu_preempted` (200 ms and 5% of the time the vCPUs wanted to run; 20% is high confidence), with the top preemptors as evidence.
- New threshold metric `vcpu_preempted_ms_per_sec`.
- The Explain `missing` list now says the guest's own steal counter is not read, and that the host's view is.
- Checked on a real 6.8 kernel with a test that pins two CPU-bound threads to one CPU (the victim is charged about half the run and the taker is named; a sleeping control is not charged; the test fails without the runnable check). Cost: about 490 ns per context switch with no VM watched, about 615 ns with ten watched, against about 435 ns before.

### FluxVM guests

- **All four backends are VMs.** QEMU, Cloud Hypervisor, Firecracker and `fluxvm-hypervisor` are named from `{state_dir}/vms.json` (`state_dir` in `/etc/fluxvm.toml`, otherwise `/var/lib/fluxvm`) and joined by pid. `runtime` is `fluxvm`. A QEMU pid already found is updated, not duplicated. Libvirt and plain QEMU that are not in the store are unchanged. See [FluxVM](docs/tap.md#fluxvm).
- **The default per-VM netns is traced.** Guest frames are attached on the host veth `vh` plus the first 8 hex digits of the VM id, not on `tap<8hex>` inside `eph-<8hex>`. Ingress is from the guest. NAT is POSTROUTING, so the event still shows the guest address. If FluxVM wrote `/run/fluxvm/ebpf/vms/<id>/iface`, that name is used instead (direct mode). A host-bridge tap keeps `tap_name`.
- **Host attribution stays `qemu-process`** for every backend. That string means the VMM's socket, not the guest.
- `cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor` and `jailer` are allowed execs, so a boot is not an unexpected-exec detection. Kernel comm is 15 characters.
- User-mode NAT still has no host interface. `shukractl doctor` names it. The live guest script still boots with `"netns": false` on a shared bridge; the netns mapping is covered by the identity tests.

### Guest DNS names

- **`guest_dns` events:** the name a guest asked for in a plain DNS query over UDP port 53, with its type, IPv4 and IPv6. The tap program only recognises a query and copies its question; the daemon decodes it (lower-cased, sanitised, cut at 253 bytes). A repeat of a name and type is announced once a minute, at most 200 per tap per second on their own budget. See [DNS names](docs/tap.md#dns-names).
- **`dns:` detection rules** matching a name by `suffix`, `exact` or `contains`.
- **`shukrad -dns-events=false`** makes the program not read DNS at all. The switch is a pinned map that the daemon sets on every start.
- `shukractl watch` prints the name, and the console's Connections page lists the names a guest looked up.
- Not seen: answers, queries over TCP, DNS over TLS or HTTPS, a second question, compressed names.

### Drops and handshakes (#7, #8)

- **New `drops` program** (Linux 5.17+): what the kernel dropped on each VM tap, by the kernel's own reason and the function that freed the packet. Shukra's isolation drops are subtracted, so another program dropping a VM's traffic (a dataplane, Cilium, a `tc` filter) is named, and a guest that is not reading its NIC shows as `FULL_RING`. It reads the tracepoint record by field name, so it survives the layout change in Linux 6.9. See [Where packets die](docs/drops.md).
- **TCP handshake outcomes on the tap:** every outbound attempt is exactly one of accepted, refused, never answered or blocked, with retransmits and the handshake time (a histogram). The same for connections made *to* the guest.
- **`guest_inbound` events**, and `dir: out|in|any` on port rules. The default stays `out`, so existing rules mean what they did.
- New threshold metrics: `guest_drops_per_sec`, `guest_connect_refused_per_sec`, `guest_connect_timeouts_per_sec`, `guest_inbound_per_sec`.
- New Explain causes `guest_traffic_dropped`, `guest_not_reading_nic` and `guest_connects_failing`; new doctor checks `vm-drops-not-shukra`, `vm-nic-not-consumed` and `vm-connects-failing`.
- `GET /api/v1/trace/drops`, `shukractl trace drops`, a Drops page in the console, and the series `shukra_tap_kernel_drops_total`, `shukra_tap_connect_outcomes_total`, `shukra_tap_connect_attempts_total` and `shukra_tap_handshake_seconds`.
- Shukra's own drop count and the kernel's are both counted from when the daemon started, so isolation from before a restart no longer hides another program's drops.
- The tap program gained new pinned maps (`tap_outcomes`, `tap_handshake_hist`, `tap_timeouts`). No existing pinned map changed layout, so an upgrade keeps isolation in force.

### Live guest test and CI (#2, #5, #6)

- `scripts/test-live-guest.sh` boots two disposable guests with fluxvm, checks attributed events, packet counts equal to the kernel's, guests reaching each other, handshake outcomes and drops, and cleans up. The `Live guest (fluxvm)` workflow runs it on a runner with `/dev/kvm` and waits for the device to become writable.
- Empty lists are `[]`, never `null`, on every endpoint.
- `scripts/deploy-remote.sh` waits for the daemon to answer before it prints status.

### Foundations (#1, #3)

- **Durable isolation.** The tap program's links and maps are pinned in the bpf filesystem, so a crash, `kill -9`, restart or stop leaves an isolated VM isolated. `shukrad -detach-all` lifts it deliberately.
- **Guest UDP:** one event per new flow, none for multicast, IPv4 and IPv6, with `proto` on port rules.
- **`shukractl doctor`** and `GET /api/v1/doctor`: what needs attention, worst first, each with a fix. It names a VM whose tap it cannot see (user-mode networking, or a tap in another network namespace).
- **Windowed Explain:** the last minute by default, `--window` up to five minutes, or the lifetime.
- Detections, isolations and the flight recorder survive a restart with `-data-dir`.

### Documentation, third pass

- New: [investigate after the fact](docs/tutorials/09-after-the-fact.md), a walkthrough of `explain --at`, `trace contention` and `incident` with real output from a hypervisor and what each cannot tell you.
- Updated for what merged since the last pass: the console tests (what they pin and why), a checklist for a new view (API route, CLI, console page), a pull-request policy (one feature each, based on `main`, never stacked, with the reason), the `no_history`, `unknown_vm` and `not_measured` causes in tutorial 4, `snapshots.jsonl` in tutorials 1 and 3, the event-list shares in `signals.md`, and the README's endpoint table.

### Documentation (#4 and the passes since)

- New: [API reference](docs/api.md), [architecture](docs/architecture.md), [testing](docs/testing.md), [development](docs/development.md), [Where packets die](docs/drops.md) and tutorial 08, [Find out why traffic is lost](docs/tutorials/08-lost-traffic.md).
- Rewritten: the README and [SECURITY](SECURITY.md); updated: signals, attribution, tap, shukractl and tutorials 01 to 06.
- New: [doctor](docs/doctor.md), every check with its status, when it fires and what to do; the "Extending what is there" checklists and the kernel-verifier lessons in [development](docs/development.md); [testing](docs/testing.md) now covers the kernel preemption test, how to compare a program's cost before and after, and what the live guest test asserts.
- Updated for DNS names, vCPU preemption and FluxVM: architecture (the DNS ring and its switch, the pinned and unpinned tap maps, the preemption tables), tap, SECURITY (the FluxVM files that are read, and that host process names now appear in the API), tutorials 01 to 06 (the `-dns-events` flag, the tap program's pins, other daemon options in `SHUKRA_EXTRA_ARGS`, the console pages, the recorder's kinds).
- Fixed stale text in the product itself: `shukractl` help still described `trace list` without `drops` and `vms` as QEMU-only, and three console navigation blurbs said enforcement "is not attached in this build" and detections were "userspace only".
- Corrected: the exit codes of `isolate` and `release` (0 even when refused: read `applied`), and the claim about KVM coverage (verified on Intel x86 hardware, not AMD or arm64).
