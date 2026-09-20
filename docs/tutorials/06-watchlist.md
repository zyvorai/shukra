# Detection rules

Rules are a userspace check on what the daemon has already recorded: connects and flows first, then looked-up names and per-VM counters (below). When one matches, Shukra writes a `detection` event. It does not drop the packet, and it does not move the match into BPF. A destination or port rule can match three kinds of connect:

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

Severity defaults differ by rule type: `destinations`, `ports`, `dns` and `tls` rules are `high` unless you say otherwise, thresholds are `medium`, and the tripwires' own detections are described in [tutorial 11](11-vmm-tripwires.md).

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

**`exec_allow`** adds to the names that are always fine: `qemu-system*`, QEMU's own `cpu`, `io`, `vhost` and `kvm` threads, and the FluxVM VMMs `cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor` and `jailer` (the kernel comm is 15 characters, so the first two long names match on `cloud-hypervis` and `fluxvm-hypervis`). It does not replace them. A boot of those binaries is not an unexpected-exec detection.

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

## Detections that need no rule

Some detections come from Shukra itself, and their names are what a `responses:` entry lists under `rules:` and what you filter on in a sink.

| Rule | Raised when | Severity |
|---|---|---|
| `unexpected-exec` | A VMM started a program that is not on the allow list (below) | high |
| `vmm-sensitive-open`, `vmm-syscall`, `vmm-flood` | A VMM, or something it started, opened a sensitive file or made a call a VMM never makes | critical, critical or high, critical: [tutorial 11](11-vmm-tripwires.md) |
| `new-destination`, `new-dns-suffix`, `new-inbound-peer`, `baseline-cap`, `baseline-forgotten` | A learned baseline saw a first sighting, hit its daily cap, or was reset by a person | medium, low, medium, low, low |
| `egress-policy-audit`, `egress-policy-blocked` | A VM under an egress policy started a connection outside its list | low, medium: [tutorial 10](10-egress-policy.md) |
| `policy-applied`, `policy-confirmed`, `policy-reverted`, `policy-removed` | An egress policy changed | low or medium, low, medium, low |
| `action-proposed`, `action-executed`, `action-refused`, `action-rejected`, `action-expired`, `action-released`, `action-dry-run` | A response decided something | by outcome |

A response can answer any of them except the `action-*` announcements, which no response ever answers.

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

Check before you reload, and confirm after:

```bash
shukractl rules check /etc/shukra/detections.yaml
sudo systemctl reload shukra
sudo journalctl -u shukra -n 5 | grep 'detection rules reloaded'
```

`rules check` runs the daemon's own strict parser on the file without touching a daemon:

```text
ok: /etc/shukra/detections.yaml would be accepted
  suppress   5m0s
  ports      smtp-egress, ssh-into-vm, dns-out
  exec_allow node_exporter
  thresholds slow-disk
  responses  contain-miners (propose)
  thresholds need the kernel programs attached, and stay quiet until a full window of history exists
```

A mistake is refused with the reason and a non-zero exit, and `shukractl doctor` reports `The detection file did not reload` when a reload failed:

```text
error: bad.yaml: yaml: unmarshal errors:
  line 5: field threshold not found in type the detection file
```

Only ports, exec allow, thresholds and responses are summarised: the `destinations`, `dns`, `tls`, `vmm` and `baselines` sections are checked but not listed.

## See a hit

```bash
shukractl security <vm>
shukractl watch --json
```

Or open Detections in the console. The event kind is `detection` and `rule` names the rule that fired. The message is the rule name plus the destination. `guest_attributed` is false for a host connect. A rule that fires on a guest connect seen on the VM tap is `guest_attributed: true` with `attribution: "guest-tap"`, and it is a separate alert from a host connect to the same address. The flight recorder keeps the same event, so `shukractl recorder <vm> --window 60s` shows it if it happened inside the window.

A connect that matches nothing is a normal `tcp_connect` event, not a detection.

To see one on purpose, with the tap program attached, add a rule for a connection made **to** a VM:

```yaml
ports:
  - port: 22
    name: ssh-into-vm
    dir: in
    severity: medium
```

Check, reload, then `ssh` to one of that host's VMs from anywhere. Within a second `shukractl security <vm>` shows a `medium` line naming the peer that connected in, `guest_attributed=true` and `attribution=guest-tap`. A second `ssh` inside the suppression time is held back and counted in `shukra_detections_suppressed_total`. Take the rule out again if you did not want it.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `field ... not found in type` | A key is misspelled or in the wrong place. The message names it and its line |
> | `name "x" is used twice` | Rule names are unique within a kind: rename one |
> | `severity "x" is not low, medium, high or critical` | Spell it as one of those four |
> | The reload logs `keeping the previous rules` | The file has a mistake. `shukractl rules check` names it. The old rules are still in force |
> | `SIGHUP ignored: no -watchlist detection file is configured` | The daemon was started with no `-watchlist`. Add it to the unit and restart |
> | A rule never fires | Does the daemon see that kind of event? Guest rules (`dir: in`, `dns`, `tls`, guest connects) need the tap program and, for names, `-dns-events` and `-tls-events` left on. Thresholds need the kernel programs. A `destinations` rule on a host connect matches the QEMU process's own sockets only. And a repeat inside `suppress` is held back on purpose |
> | It fired once and not again | Suppression: same rule, same VM, same destination inside five minutes is one alert. `suppress: 0s` alerts every time |

## What you should not add

Do not put "block this CIDR" in the YAML and expect it to happen. A detection only notices. Enforcement is the separate, deliberate `isolate` step, which drops a whole VM's tap traffic except an explicit management allow list. See [Guest traffic and isolation](../tap.md).
