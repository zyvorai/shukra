# Changelog

Shukra has no tagged release yet. This lists what has merged to `main`, newest first, by pull request. Pushing a `v*` tag will cut the first release (see [development](docs/development.md#releasing)).

## Unreleased

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

### Documentation (#4 and this pass)

- New: [API reference](docs/api.md), [architecture](docs/architecture.md), [testing](docs/testing.md), [development](docs/development.md), [Where packets die](docs/drops.md) and tutorial 08, [Find out why traffic is lost](docs/tutorials/08-lost-traffic.md).
- Rewritten: the README and [SECURITY](SECURITY.md); updated: signals, attribution, tap, shukractl and tutorials 01 to 06.
- Corrected: the exit codes of `isolate` and `release` (0 even when refused: read `applied`), and the claim about KVM coverage (verified on Intel x86 hardware, not AMD or arm64).
