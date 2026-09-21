# Egress policy: which networks a VM may connect to

A VM's baseline says where it normally connects. An **egress policy** turns that into a rule the tap program can hold it to: the VM may start connections to these networks, and to nothing else. Because a wrong policy cuts a working VM off, it is built to be tried before it is believed:

1. **Learn.** Propose a list from what the VM has been seen to do (`shukractl policy learn`).
2. **Audit.** Put the VM under the list in audit mode. Nothing is dropped. What *would* have been is counted and reported, so a person can see what the list gets wrong before it costs anything.
3. **Enforce.** Only then drop it, with a timer: unless a person confirms, the VM goes back to what it had.

It is off for every VM until someone applies a policy. Nothing changes for a VM without one.

It is the [tap program](tap.md)'s second use of the same hook that does [isolation](tap.md#isolate): isolation drops everything except the management network, and a policy drops only what the VM starts outside a list. The list is usually [learned](baselines.md), and what a policy drops shows up in the tap's counters and connect outcomes, so [where packets die](drops.md) does not blame anyone else for it.

## The workflow

```bash
shukractl policy learn web                 # what the baseline says web talks to, and how that differs from what it has
shukractl policy apply web --mode audit --from-baseline
shukractl policy web                       # what audit has counted, per tap, after a day or two
# Add what it wrongly flagged, then:
shukractl policy apply web --mode enforce --confirm 10m
# ... watch the VM, and if it is well:
shukractl policy confirm web               # it stays; otherwise it goes back to audit after ten minutes
shukractl policy remove web                # lift it altogether
```

`web` is the VM's name as `shukractl vms` prints it. The VM has to be in the current scan and have a tap Shukra can attach to: a VM that is stopped, or on user-mode networking, is refused. A policy for a VM that is not running is kept, shown as `(VM not running)`, and put back when a VM of that name is seen again. A policy belongs to a name, so a renamed VM starts with none.

`--from-baseline` needs [learned baselines](baselines.md) on. Without them give the networks yourself, `--allow 203.0.113.0/24,2001:db8::/32,10.1.2.3` (a bare address is a /32 or /128; host bits are cleared, so `10.1.2.3/24` is `10.1.2.0/24`). `apply` with no list keeps the VM's current one, so moving from audit to enforce does not repeat it. `--mode off` is the same as `remove`.

`learn` shows what the baseline proposes and how it differs from what the VM has now (`+` is new to the policy, `-` is on the policy and no longer seen):

```text
$ shukractl policy learn web
POLICY PROPOSAL  web  3 networks
    10.20.0.0/24
    198.51.100.0/24
    2001:db8:1::/64
    + 203.0.113.0/24  (against its current policy)
    - 192.0.2.0/24  (against its current policy)
  audit it first: shukractl policy apply web --mode audit --from-baseline
```

A VM still inside its baseline's learning period gets `(still learning: it may be incomplete)` and a note, because what it has not done yet is not on the list. A proposal is a list of the baseline's `destination` items, which are IPv4 /24 and IPv6 /64 networks: it can be edited before it is applied, by giving `--allow` instead.

## What it needs

| To... | The daemon needs |
|---|---|
| Audit | The tap program loaded, and the VM present with a tap. Nothing else: no allow list, no `-data-dir` |
| Keep an audit policy across a restart | `-data-dir`. Without one the record is in memory only (see [Files](#files) for what a crash then leaves) |
| Enforce | All of: the management allow list (`-isolate-allow`), a `-data-dir`, a non-empty list, and either `--confirm <duration>` or `--permanent` |
| Propose from a baseline | A `baselines:` section in the rules file, and a VM the baseline has seen |

`shukractl policy` says `(audit only: enforcing needs -data-dir, so that the record survives a restart)` when there is no data directory.

## What it judges, and what it does not

The policy judges **new things the guest starts**, by the network they go to:

| Judged | Not judged |
|---|---|
| A TCP SYN: a new outbound connection | Established connections, and a server answering one (SYN-ACK and data are not new) |
| A UDP datagram that is not multicast and is not an answer | ICMP, ARP, IPv6 neighbour discovery, anything that is not TCP or UDP |
| | Multicast and broadcast (mDNS, DHCP discovery) |
| | A UDP datagram that answers one the guest received: the same peer and the same ports, within the last minute |

So a VM that **serves** things keeps working under enforcement: a client connects in and is answered, whatever address it came from. A UDP server answers whoever asked. What is cut off is the VM *starting* a connection to somewhere the list does not name.

The **management allow list** (`-isolate-allow`) is never judged, whatever a policy says. It is the floor: a wrong policy cannot cut a VM off from the network that manages it. Enforcing is refused without one.

Counts are of packets, not of connections. A guest that retries a dropped SYN is counted each time (`judged`, and `dropped` under enforcement), so 14 dropped can be four connections. `judged` is every SYN and every non-multicast UDP datagram the guest sent, whether or not it was outside the list.

## Modes

| Mode | What it does |
|---|---|
| `off` | Nothing is judged. The same as no policy |
| `audit` | What would be dropped is counted and reported, and passes. Needs only the tap program: no management allow list |
| `enforce` | What is outside the list is dropped, as isolation drops. Needs the management allow list, a `-data-dir`, and a way back (below) |

In audit mode a connection outside the list is a `guest_connect` or `guest_flow` event with `policy: "audit"`, and a low **`egress-policy-audit`** detection: *"web opened tcp to 198.51.100.7:443, outside its egress policy: it would have been dropped (audit mode)"*. Under enforcement the event is `blocked: true` with `policy: "enforce"`, and the detection is a medium **`egress-policy-blocked`**. Both are held back per VM, mode, /24 or /64 network and protocol for the rules file's `suppress` time (5 minutes by default), as a baseline's first sighting is, so a VM that keeps trying one place is one detection. The counters and the events are separate: `auditPackets` counts every datagram of a UDP stream to an address outside the list, and the event is one per flow.

Every change to a policy is itself a detection, so a webhook hears of it:

| Detection | Severity | When |
|---|---|---|
| `policy-applied` | low for audit, medium for enforce | A policy is applied or changed. The message names who, where the list came from (`manual` or `baseline`) and, for an unconfirmed one, when it goes back |
| `policy-confirmed` | low | `policy confirm` |
| `policy-reverted` | medium | A timer ran out and the VM went back to what it had |
| `policy-removed` | low | `policy remove` (or `--mode off`) |

## What stops a wrong policy doing harm

- **Audit first**, and audit needs nothing. It is the only mode that needs no allow list, so trying a policy out is always possible.
- **Enforcing needs `--confirm <duration>` (30 seconds to 24 hours) or `--permanent`, not both.** With a duration, the policy goes back to what the VM had before, unless a person runs `policy confirm`: to the audit it replaced, to an earlier enforcing list, or to none. Changing an unconfirmed policy does not move the target: it still goes back to what came before all of it. Going from enforce back to audit is immediate and has no timer, since it can only open the VM up.
- **The timer is in the record, and the record is saved before the kernel is changed.** The record is never behind what is enforced. Timers are checked every two seconds. A daemon that was down when a timer ran out reverts on its first pass after it starts, and until then the kernel keeps enforcing.
- **A change that fails is put back**, in the record and in the kernel: a list that only got part of the way in does not stay. If some of a VM's taps took the policy and some did not, it stays on the ones that did and the row says `PROBLEM some taps did not take it`.
- **Enforcing needs a record that survives a restart** (`-data-dir`), because the kernel keeps enforcing without the daemon, and a policy nobody has a record of can never be reverted. It also needs a non-empty list: cutting a VM off from everything is what [isolate](tap.md#isolate) is for.
- **The kernel keeps enforcing without the daemon.** The policy lives in pinned maps, like isolation. A crash, a restart or a graceful stop leaves an enforcing tap enforcing, and the next start adopts it. A tap that is only auditing is detached by a graceful stop and put back by the next start. `shukrad -detach-all` lifts the kernel side with the daemon down, but it does not touch `policies.json`: the next start puts every recorded policy back. To end one for good, `shukractl policy remove <vm>`.
- **What the record says is what the kernel is made to do**, when a link appears and again every two seconds, and after a restart. One difference is reported (in `policy` and the doctor), not hidden.
- **A tap enforcing a policy nobody recorded is an orphan** (the record was lost, or something else set it). The daemon does not guess about it: it is shown in `policy`, `doctor` warns, and `shukractl policy remove <vm>` puts the tap right whether or not there was a record. A policy file that cannot be read is set aside as `policies.json.corrupt` and the taps it named show up as orphans.
- **Isolation still wins, and does not disturb the policy.** An isolated VM is dropped as always; releasing it leaves its policy as it was.
- **It is announced.** Applying, confirming, reverting and removing a policy each raise a detection (`policy-applied`, `policy-confirmed`, `policy-reverted`, `policy-removed`), so a webhook hears of a change to what a VM may do.

A person with the admin key can still make a wrong policy. The record of who did is the key id (`admin:` and six hex characters) plus the `X-Shukra-Actor` label when the client sent one (`shukractl` for the CLI). It is not a person's name: the API key is one key, not a login.

## What it does not do

- **It is not a firewall.** It decides where a VM may *start* connections. ICMP is not judged, and a guest that sends TCP segments that are not a SYN, or crafts packets, is not stopped by it: a connection cannot be *established* without a SYN, which is what it judges.
- **Networks only.** No ports, no names. The baselines it learns from are IPv4 /24 and IPv6 /64 networks, so a proposal is as coarse as that. (Policy by server name, from [TLS server names](tap.md#tls-server-names), is not part of this.)
- **A UDP stream a guest sends to a peer that has gone quiet for a minute is judged** as a new flow. A peer's every datagram to the guest renews the minute (to within 5 seconds).
- **A new tap is not left open until the next scan.** A netlink notification attaches the program and then writes the VM's saved policy before that tap is reported as covered. The two-second scan is only the backstop, if a notification is missed. While an enforcing VM has a live tap and no program, that is a `tap-uncovered` detection. `-quarantine-uncovered` (off by default) drops that tap, except the management allow list, until the policy is on it. Enforcement across a daemon restart has no such gap: the maps are pinned.
- **DNS and DHCP need to be on the list.** A resolver the VM uses is a destination like any other, so it has to be listed or lookups stop; the baseline learns it because the flow to it was seen. DHCP discovery is broadcast and is not judged, but a renewal sent straight to the DHCP server is.
- **A baseline learns what the guest attempted**, including a connection a policy dropped, so a VM that has been enforced for a while will propose networks it was never allowed to reach. Read a proposal made from an enforcing VM against its current list (`+` lines).
- **A restart forgets which UDP peers wrote to the guest.** That table is not pinned, so an answer to a datagram that arrived before the restart is judged as a new flow until the peer sends again.
- IPv6 extension headers and VLAN tags are not looked through, as for everything the tap program does.

## Reading it

```text
$ shukractl policy
EGRESS POLICY  2 VMs
  web  enforce  12 networks (baseline), set by shukractl at 2026-09-20T03:00:00Z
      UNCONFIRMED: goes back to audit with 12 networks at 2026-09-20T03:10:00Z unless confirmed: shukractl policy confirm web
      vnet3  kernel enforce  judged 4210 new connections, 14 dropped (1400 bytes)
  db  audit  3 networks (manual), set by shukractl at 2026-09-19T14:00:00Z
      vnet6  kernel audit  judged 88 new connections, 7 would have been dropped (700 bytes)
```

- **`judged`** is every new connection or datagram the policy looked at (packets, see above), so it is the denominator: 14 dropped of 4210 is a policy that is nearly right.
- **`kernel`** is the mode the tap program is in, which is the policy's unless something is wrong; a difference is `PROBLEM` and a doctor warning.
- **`ORPHAN`** lines are taps the kernel applies a policy on with no record of one; the line says the command that lifts it.
- **`/metrics`** has `shukra_egress_policy_mode{vm,tap}` (0, 1, 2), `shukra_egress_policy_unconfirmed{vm}`, `shukra_egress_checked_total`, `shukra_egress_audit_packets_total`, `shukra_egress_audit_bytes_total`, `shukra_egress_dropped_packets_total` and `shukra_egress_dropped_bytes_total` (each `{vm,tap}`), only for a VM that has a policy. Alert on `shukra_egress_policy_unconfirmed == 1` for longer than you would like a VM to hold a timer.
- **A drop is Shukra's own.** Policy drops are counted in the tap's `droppedPackets` and in the connect outcomes as *blocked*, like isolation's, so the [drops](drops.md) accounting does not blame someone else for them. `shukra_tap_dropped_packets_total` counts both (its help text still says only isolation).
- **The doctor** has one `egress-policy` finding, and it says the worst thing first: an orphan (warn), then a kernel that disagrees with a policy (warn), then policies waiting to be confirmed (warn), and otherwise `ok` with how many are audit and enforce and how many packets audit would have dropped. Only present once a policy exists or the kernel applies one. See [doctor](doctor.md).

## How do I know it works

On a VM you can afford to disturb, in this order:

1. **The kernel has it.** After `apply`, `shukractl policy web` shows each tap as `kernel audit` (or `kernel enforce`), not `kernel off`, and `judged` rises while the VM is in use. If `kernel` differs from the mode on the first line, the row says `PROBLEM` and the daemon puts it right on the next pass (immediately when netlink reports the link, otherwise within two seconds).
2. **Audit sees the stray.** From the guest, connect to an address outside the list. `would have been dropped` rises by at least one, `shukractl watch --json` shows a `guest_connect` with `"policy":"audit"`, and `shukractl security web` lists an `egress-policy-audit` detection. The connection itself still works.
3. **The floor holds.** A connection to the management network works in every mode.
4. **Enforce drops the stray and only the stray.** Apply with `--confirm 30s` (the shortest timer). The same connection now fails, the event says `"blocked":true,"policy":"enforce"`, `dropped` rises, and `shukractl trace tap --vm web` counts it under `blocked`. A connection to a listed network, a client connecting in, and the management network all still work.
5. **The way back works.** Wait 30 seconds without confirming: a `policy-reverted` detection appears and `shukractl policy web` shows the mode it went back to.

## Troubleshooting

What it looks like when it is wrong, and what to do.

| What you see | What it means | What to do |
|---|---|---|
| `apply` says `no VM named "x" is in the current scan` (404) | The name is not one `shukractl vms` prints, or the VM is stopped | Use the name from `shukractl vms` |
| `apply` says `has no tap interface` (409) | User-mode networking, or the daemon could not find the tap. See [tap](tap.md#troubleshooting) | Nothing can be put on such a VM |
| `apply` says `the tap program is not loaded` (409) | The tap program is detached (Linux before 6.6, or it failed to load) | `shukractl programs` says why |
| `apply ... enforce` says `enforcing needs the management allow list` (409) | No `-isolate-allow`, or it could not be loaded | Start the daemon with `-isolate-allow <management CIDRs>`, then restart it |
| `apply ... enforce` says `enforcing needs -data-dir` (409) | There is nowhere to keep the record | Start with `-data-dir` (the shipped unit does) |
| `apply ... enforce` says `an empty list would cut the VM off` (409) | The list has no networks | Give one, or use `isolate` if that is what you mean |
| `apply ... enforce` says `needs --confirm <duration>` (400) | Neither `--confirm` nor `--permanent` | Give one. A duration is 30s to 24h |
| `apply` says `no list of networks` (400) | No `--allow`, no `--from-baseline`, and the VM has no policy to keep | Give a list |
| `--from-baseline` says `learned baselines are off` (409) | The rules file has no `baselines:` section | Add one, or give `--allow` |
| `--from-baseline` says `the baseline has not seen a VM named` (404) | The daemon has seen no guest events from it yet | Wait, or `--allow` |
| `confirm` says `nothing waits for confirmation` (409) | The policy is audit, is permanent, or was already confirmed | Nothing to do |
| The policy went back by itself | The timer ran out. There is a `policy-reverted` detection | Apply again with a longer `--confirm`, or `--permanent` |
| `PROBLEM the kernel has vnet3 in mode X, and the policy says Y` | The kernel and the record disagree, for example a tap that came back with a new name | It is put right on the next pass: immediately when netlink reports the link, otherwise within two seconds. If it stays, the daemon's log has `policy: making <tap> match` and why |
| `PROBLEM some taps did not take it` | A VM with several taps got the policy on some | The problem line names which and why. Apply again, or `remove` |
| `ORPHAN` and a doctor warning | A tap has a policy and there is no record. The record was lost or `policies.json` was set aside as `.corrupt`, or an audit policy was applied with no `-data-dir` and the daemon then crashed | `shukractl policy remove <vm>` puts the tap right. Then apply again if you want one |
| `judged` stays at 0 | The VM is idle, or the row's `kernel` is `off`, or a different tap of the VM is the busy one | `shukractl policy` lists every tap of the VM |
| Under enforcement a connection that should be dropped is not | It went to the management network, or to a network the list covers at /24 or /64 granularity, or was an answer to something the guest received, or was multicast, or was not a SYN | The list is networks, not hosts: `198.51.100.7` is on it if `198.51.100.0/24` is |
| A VM lost DNS or NTP under enforcement | The resolver or time server is a destination like any other and is not on the list | Add it. Audit would have counted it |
| The list has networks the VM was never allowed to reach | The baseline learns what a guest attempted, including what a policy dropped | Read the `+` lines of `policy learn` before applying |
| The policy is back after `shukrad -detach-all` | `-detach-all` does not touch `policies.json` | `shukractl policy remove <vm>` while the daemon is up |

## Limits

| What | Limit |
|---|---|
| Networks per VM | 1,024. More is refused |
| Networks across all VMs | 16,384 for IPv4 and 16,384 for IPv6 (the kernel's tries). The management allow list is separate and holds 256 of each |
| Confirmation time | 30 seconds to 24 hours |
| Timer check | Every 2 seconds |
| Kernel-versus-record check | On a netlink link notification, and every 2 seconds |
| UDP answers remembered | 65,536 flows (an LRU that is not pinned, so a restart forgets them); an answer is allowed for 60 seconds after the datagram it answers |

## API

| Route | |
|---|---|
| `GET /api/v1/policy[?vm=]` | Every policy (`mode`, `allow`, `source`, `by`, `applied`, `present`, `revert`, and per tap the kernel mode and counters), the orphans, and whether records are kept across a restart (`persisted`) |
| `GET /api/v1/policy/proposal?vm=` | What the baseline proposes, and how it differs from the VM's current policy (`added`, `removed`) |
| `POST /api/v1/policy/apply` | Admin key. `{"vm", "mode", "allow"?, "fromBaseline"?, "confirm"?, "permanent"?}`. `mode` is `off`, `audit` or `enforce`; `confirm` is a Go duration such as `"10m"` |
| `POST /api/v1/policy/confirm`, `.../remove` | Admin key. `{"vm"}` |

A failure is `400` for a request that is wrong, `404` for a VM or policy that is not there and `409` for one that is refused (with the reason), each with the reason as text. A policy that could not be saved, or that no tap of the VM took, is a `500` with the reason, and nothing has changed. A change is recorded as the key id of the admin key, with the `X-Shukra-Actor` label when one was sent.

## Files

`policies.json` under `-data-dir` (mode 0600) holds every policy. It is rewritten whole, atomically and synced, on every change. It names VMs and the networks each may reach, so it is as sensitive as `baselines.json`. A file that cannot be read, or whose `version` is not 1, is set aside as `policies.json.corrupt` and the daemon starts with no policies; the taps that still enforce one show as orphans.

To end every policy at once with the daemon down: `shukrad -detach-all` (kernel side), then move `policies.json` aside before starting the daemon again, or the record puts them back.

Without `-data-dir` an audit policy is kept in memory only. A graceful stop detaches an auditing tap, so nothing is left behind, but a crash leaves the kernel auditing with no record, which shows as an orphan.

## Cost

With no policy on a tap, the program does one extra read and compare per packet, about **7 to 10 ns** on the reference host (a data segment 76 to 78 ns before, 86 to 87 ns after), which is about 1% of a core at a million packets a second. A tap under a policy adds a trie lookup per new connection or datagram, and a flow-table update per datagram sent to the guest. Measured with [`scripts/bench-tap.sh`](../scripts/bench-tap.sh); see [testing](testing.md).

## How it was checked

- **`scripts/test-tap-progrun.sh`** loads a private copy of the program and runs hand-built packets through it with `BPF_PROG_TEST_RUN`, so the verdict asserted is the kernel program's own: nothing judged while off; audit lets everything through and counts exactly what would have been dropped; enforce drops a SYN or a UDP datagram outside the list and passes one inside; the management network passes though it is not on the list; established TCP, a SYN-ACK, ICMP, multicast and broadcast are not judged; a UDP answer passes only after the datagram it answers, on the same ports and peer; IPv4 and IPv6, a /0, a /32 and a /128; one tap's list is not another's; isolation wins and is not counted against the policy. It runs safely on a production host.
- **Section 15 of `scripts/test-tap.sh`** runs the daemon: audit, enforce, the floor, a server still working, the refusals (no allow list, no timer), the timer reverting to the audit it replaced, `kill -9`, a restart and a graceful stop, a lost record and `remove`, and isolation together with a policy.
- **The live guest test** puts an audit policy on a real KVM guest, checks it marks exactly the connections outside its list and drops nothing, and takes it off again. See [testing](testing.md).

## See also

The [walkthrough](tutorials/10-egress-policy.md) takes one VM from learning to a confirmed policy. [Learned baselines](baselines.md), where the list comes from. [The tap program](tap.md), which does the judging, and [isolation](tap.md#isolate), which a policy does not replace. [Where packets die](drops.md), which counts a policy's drops as Shukra's own. [Responses](responses.md), which can isolate a VM when a detection fires: `egress-policy-blocked` is a detection a response can name.
