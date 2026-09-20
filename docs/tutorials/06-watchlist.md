# Detection rules

Rules are a userspace check on connects. When one matches, Shukra writes a `detection` event. It does not drop the packet, and it does not move the match into BPF. A rule can match three kinds of connect:

| Seen as | Where it comes from | `guest_attributed` |
|---|---|---|
| A host connect | `tcp_v4_connect` and `tcp_v6_connect`: a socket the **VMM** opened. `attribution` is `qemu-process` for QEMU and for every FluxVM backend | `false` |
| A guest connect or UDP flow | The tap program, on the VM's host interface: what the **guest** sent. For FluxVM's default netns that interface is the host veth | `true` |
| A connection made **to** the guest | The tap program: a `guest_inbound` event, matched on the peer and the guest port | `true` |

A detection keeps the attribution of the event that caused it. A hit on a **host** connect means the VMM opened a socket to an address you listed, and does not mean a process inside the guest did: say that when you page someone. A hit on a **guest** event means that VM's guest sent (or received) that traffic, seen on its host interface, though still not which process inside it. Only a VM whose interface Shukra can attach to has guest events; `shukractl doctor` names the ones that do not. FluxVM's default netns is attached; see [FluxVM](../tap.md#fluxvm).

## File

```yaml
destinations:
  - cidr: 185.0.0.0/8
    severity: high
    name: unexpected-egress
  - cidr: 203.0.113.10
    name: lab-sink
```

| Field | |
|---|---|
| `cidr` | CIDR, or a single IP (treated as `/32` or `/128`) |
| `name` | Shown on the detection |
| `severity` | Optional. Default `high` |

For a `destinations` rule, the address that matters is where the VM connected to, or, for a connection made **to** the VM, the peer that connected in, so a watched network reaching into a VM fires too and the message says "connected in from". `ports` rules take `proto` (`tcp` by default, `udp` or `any`) and `dir` (`out` by default, `in` for a connection made to the VM and matched on the port it reached, or `any`), so a rule written before either existed means what it always did.

`configs/detections.example.yaml` is the sample. An empty file is an empty list, not an error. A bad CIDR refuses to start the daemon.

The same file holds the other rule types below. It is read strictly: an unknown key, a bad severity (`low`, `medium`, `high`, `critical`), a repeated rule name or an out-of-range value is an error, so a misspelled `threshold:` cannot quietly turn a rule off.

## More rules

```yaml
suppress: 5m           # default; 0s alerts every time

ports:                 # a connect (or, with proto, a UDP flow) to this destination port
  - port: 25
    name: smtp-egress
    severity: medium
  - port: 22
    name: ssh-into-vm
    dir: in            # out (the default: the VM connected), in (a connection made TO the VM), or any
  - port: 53
    name: dns-out
    proto: udp         # tcp (the default), udp or any

dns:                   # names the guest looked up over DNS (UDP port 53), one of suffix / exact / contains per rule
  - name: crypto-pool
    suffix: nanopool.org      # the name and everything under it, on a label boundary
    severity: high
  - name: paste-site
    contains: pastebin
    severity: medium

tls:                   # the server name in a guest's TLS ClientHello, same three matchers (see docs/tap.md)
  - name: doh-google
    suffix: dns.google
    severity: medium

baselines:             # optional: learn what is normal for each VM, and report what is new (see docs/baselines.md)
  learn: 24h

responses:             # optional: what to do when a detection fires (see docs/responses.md)
  - name: contain-miners
    rules: [crypto-pool]
    action: isolate      # the only action. mode: propose (default) waits for a person to approve

exec_allow:            # may start under a VMM without an alert; lowercase prefix
  - node_exporter

thresholds:            # per VM, over a window
  - name: slow-disk
    metric: block_write_p99_ms
    value: 50
    window: 30s        # 5s to 10m, default 30s
    severity: medium   # default for thresholds
```

**`dns`** rules match the name the guest asked for, in lower case (the rule is lower-cased too). `suffix: example.com` matches `example.com` and `a.b.example.com`, not `badexample.com`; `exact` is the whole name; `contains` is a substring. A rule takes exactly one of the three. The detection says the guest asked, is `guest_attributed`, and is held back for the suppression time per rule, VM and name. Names are only recorded while `shukrad` runs without `-dns-events=false`, so a `dns` rule says nothing on a daemon that has names off. See [DNS names](../tap.md#dns-names).

**`tls`** rules are `dns` rules for the server name in a guest's TLS ClientHello (`suffix`, `exact` or `contains`, one each, lower case). They catch a guest that reaches a name without asking DNS for it, or over DNS-over-HTTPS: `- {name: doh, suffix: dns.google}`. A `dns` rule does not judge a TLS name and a `tls` rule does not judge a lookup, so give both if you want both. Names are only recorded while `shukrad` runs without `-tls-events=false`. See [TLS server names](../tap.md#tls-server-names).

**`vmm`** changes what the VMM tripwires count. They watch every QEMU process, and what it started, for the files it opens and the calls a VMM never makes, with built-in defaults and no section needed: `paths` adds sensitive paths (`*` is one path segment), `ignore` exempts one (a VM image kept under a directory the list names), `syscalls` narrows the calls, and `defaults: false` leaves only your `paths`. See [VMM tripwires](../vmm-tripwires.md).

**`baselines`** is the other way round from every rule above: no one names what is bad, the daemon learns what each VM normally does for `learn` (24 hours by default) and then reports the first sighting of a network, a site or an inbound peer it has not seen. It is off unless the section is present, and it needs `-data-dir`. See [learned baselines](../baselines.md).

**`responses`** say what to do when a detection fires, and the only thing they can do is isolate the VM. By default a response **proposes** and a person approves; `mode: enforce` acts on its own but must name the rules it answers, and `guardrails` protect VMs and cap how much can happen. See [responses](../responses.md).

**`exec_allow`** adds to the names that are always fine: `qemu-system*`, QEMU's own `cpu`, `io` and `vhost` threads, and the FluxVM VMMs `cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor` and `jailer` (the kernel comm is 15 characters, so the first two long names match on `cloud-hypervis` and `fluxvm-hypervis`). It does not replace them. A boot of those binaries is not an unexpected-exec detection.

**Thresholds** compare a metric against the counters one `window` ago, per VM:

| Metric | Value |
|---|---|
| `block_read_p99_ms`, `block_write_p99_ms` | p99 of the requests that finished in the window |
| `wakeup_delay_ms` | mean scheduler wakeup delay in the window |
| `kvm_exit_latency_p99_ms` | p99 host time handling a KVM exit in the window. Halts are excluded, since they are guest idle |
| `runqueue_delay_p99_ms` | p99 wait for a host CPU after a wakeup, across the VM's threads |
| `vcpu_preempted_ms_per_sec` | Milliseconds per second the VM's vCPU threads were runnable but off a host CPU, summed over its vCPUs (so a 4-vCPU VM can exceed 1000). The host's view of losing the CPU, not the guest's steal counter |
| `block_read_bytes_per_sec`, `block_write_bytes_per_sec`, `block_iops` | Throughput and request rate on the QEMU I/O thread |
| `guest_connect_refused_per_sec`, `guest_connect_timeouts_per_sec` | The guest's own TCP connections that were refused, or that nobody answered. Needs the tap program |
| `guest_inbound_per_sec` | Connections per second attempted to the guest. Needs the tap program |
| `guest_drops_per_sec` | Packets per second the kernel dropped on the VM's taps that Shukra did not (another program, not isolation). Needs the drops program; without it a rule says nothing |
| `kvm_exits_per_sec` | KVM exits per second |
| `tcp_retransmits_per_sec` | retransmits per second |

`op` is `>` (default) or `>=`. A rule says nothing until a full window of history exists, a VM that appeared mid-window is skipped, and a counter that went backwards (a thread exited) is skipped rather than guessed at. No I/O in the window means no p99, so no alert. Latency comes from a log2 histogram, so a p99 is a bucket edge and can read up to 2x high. These are the QEMU process's counters, not the guest's. Thresholds need the kernel programs attached; on a detached build they never fire.

## Suppression

The first detection goes through. A repeat with the same key inside `suppress` is held back and counted in `shukra_detections_suppressed_total`. The next one that goes through says `(N similar suppressed)`. The key is the rule plus the VM, plus the destination for connect rules, the name for DNS rules and the process name for exec, so a new destination or a new name is a new alert. The raw `tcp_connect` events are still recorded; only the alert is collapsed. The suppression table is bounded, and if it fills with live keys a detection is let through rather than dropped.

Where the alerts go: [Alert sinks](07-alert-sinks.md).

## Load it

```bash
shukrad -watchlist /etc/shukra/detections.yaml
```

`deploy-remote.sh` copies the example to `/etc/shukra/detections.yaml` and points the unit at it. Edit that file on the host, then reload it without dropping the recorder or the event list. Suppression state survives a reload:

```bash
sudo systemctl reload shukra    # sends SIGHUP to shukrad
```

If the new file has any mistake, `shukrad` logs `detection file reload failed, keeping the previous rules` and the old rules stay in force. Only a restart with a bad file refuses to start. Units installed before this change have no `ExecReload`; `kill -HUP $(pidof shukrad)` does the same thing.

## See a hit

```bash
shukractl security <vm>
shukractl watch --json
```

Or open Detections in the console. The event kind is `detection` and `rule` names the rule that fired. The message is the rule name plus the destination. `guest_attributed` is false for a host connect. A rule that fires on a guest connect seen on the VM tap is `guest_attributed: true` with `attribution: "guest-tap"`, and it is a separate alert from a host connect to the same address. The flight recorder keeps the same event, so `shukractl recorder <vm> --window 60s` shows it if it happened inside the window.

A connect that matches nothing is a normal `tcp_connect` event, not a detection.

## What you should not add

Do not put "block this CIDR" in the YAML and expect it to happen. A detection only notices. Enforcement is the separate, deliberate `isolate` step, which drops a whole VM's tap traffic except an explicit management allow list. See [Guest traffic and isolation](../tap.md).
