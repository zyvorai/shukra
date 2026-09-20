# Changelog

Shukra has no tagged release yet. This lists what has merged to `main`, newest first, by pull request. Pushing a `v*` tag will cut the first release (see [development](docs/development.md#releasing)).

## Unreleased

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

### Documentation (#4 and the passes since)

- New: [API reference](docs/api.md), [architecture](docs/architecture.md), [testing](docs/testing.md), [development](docs/development.md), [Where packets die](docs/drops.md) and tutorial 08, [Find out why traffic is lost](docs/tutorials/08-lost-traffic.md).
- Rewritten: the README and [SECURITY](SECURITY.md); updated: signals, attribution, tap, shukractl and tutorials 01 to 06.
- New: [doctor](docs/doctor.md), every check with its status, when it fires and what to do; the "Extending what is there" checklists and the kernel-verifier lessons in [development](docs/development.md); [testing](docs/testing.md) now covers the kernel preemption test, how to compare a program's cost before and after, and what the live guest test asserts.
- Updated for DNS names, vCPU preemption and FluxVM: architecture (the DNS ring and its switch, the pinned and unpinned tap maps, the preemption tables), tap, SECURITY (the FluxVM files that are read, and that host process names now appear in the API), tutorials 01 to 06 (the `-dns-events` flag, the tap program's pins, other daemon options in `SHUKRA_EXTRA_ARGS`, the console pages, the recorder's kinds).
- Fixed stale text in the product itself: `shukractl` help still described `trace list` without `drops` and `vms` as QEMU-only, and three console navigation blurbs said enforcement "is not attached in this build" and detections were "userspace only".
- Corrected: the exit codes of `isolate` and `release` (0 even when refused: read `applied`), and the claim about KVM coverage (verified on Intel x86 hardware, not AMD or arm64).
