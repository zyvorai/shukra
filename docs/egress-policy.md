# Egress policy: which networks a VM may connect to

A VM's baseline says where it normally connects. An **egress policy** turns that into a rule the tap program can hold it to: the VM may start connections to these networks, and to nothing else. Because a wrong policy cuts a working VM off, it is built to be tried before it is believed:

1. **Learn.** Propose a list from what the VM has been seen to do (`shukractl policy learn`).
2. **Audit.** Put the VM under the list in audit mode. Nothing is dropped. What *would* have been is counted and reported, so a person can see what the list gets wrong before it costs anything.
3. **Enforce.** Only then drop it, with a timer: unless a person confirms, the VM goes back to what it had.

It is off for every VM until someone applies a policy. Nothing changes for a VM without one.

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

`--from-baseline` needs [learned baselines](baselines.md) on. Without them give the networks yourself, `--allow 203.0.113.0/24,2001:db8::/32,10.1.2.3` (a bare address is a /32 or /128). `apply` with no list keeps the VM's current one, so moving from audit to enforce does not repeat it.

## What it judges, and what it does not

The policy judges **new things the guest starts**, by the network they go to:

| Judged | Not judged |
|---|---|
| A TCP SYN: a new outbound connection | Established connections, and a server answering one (SYN-ACK and data are not new) |
| A UDP datagram that is not multicast and is not an answer | ICMP, ARP, IPv6 neighbour discovery, anything that is not TCP or UDP |
| | Multicast and broadcast (mDNS, DHCP discovery) |
| | A UDP answer to a peer that sent the guest a datagram in the last minute |

So a VM that **serves** things keeps working under enforcement: a client connects in and is answered, whatever address it came from. A UDP server answers whoever asked. What is cut off is the VM *starting* a connection to somewhere the list does not name.

The **management allow list** (`-isolate-allow`) is never judged, whatever a policy says. It is the floor: a wrong policy cannot cut a VM off from the network that manages it. Enforcing is refused without one.

## Modes

| Mode | What it does |
|---|---|
| `off` | Nothing is judged. The same as no policy |
| `audit` | What would be dropped is counted and reported, and passes. Needs only the tap program: no management allow list |
| `enforce` | What is outside the list is dropped, as isolation drops. Needs the management allow list, a `-data-dir`, and a way back (below) |

In audit mode a connection outside the list is a `guest_connect` or `guest_flow` event with `policy: "audit"`, and a low **`egress-policy-audit`** detection: *"web opened tcp to 198.51.100.7:443, outside its egress policy: it would have been dropped (audit mode)"*. Under enforcement the event is `blocked: true` with `policy: "enforce"`, and the detection is a medium **`egress-policy-blocked`**. Both are held back per VM, mode, network and protocol, as a baseline's first sighting is, so a VM that keeps trying one place is one detection.

## What stops a wrong policy doing harm

- **Audit first**, and audit needs nothing. It is the only mode that needs no allow list, so trying a policy out is always possible.
- **Enforcing needs `--confirm <duration>` (30 seconds to 24 hours) or `--permanent`.** With a duration, the policy goes back to what the VM had before, unless a person runs `policy confirm`: to the audit it replaced, to an earlier enforcing list, or to none. Changing an unconfirmed policy does not move the target: it still goes back to what came before all of it.
- **The timer is in the record, and the record is saved before the kernel is changed.** The record is never behind what is enforced. A daemon that was down when a timer ran out reverts on its first pass after it starts.
- **A change that fails is put back**, in the record and in the kernel: a list that only got part of the way in does not stay.
- **Enforcing needs a record that survives a restart** (`-data-dir`), because the kernel keeps enforcing without the daemon, and a policy nobody has a record of can never be reverted. It also needs a non-empty list: cutting a VM off from everything is what [isolate](tap.md#isolate) is for.
- **The kernel keeps enforcing without the daemon.** The policy lives in pinned maps, like isolation. A crash, a restart or a graceful stop leaves an enforcing tap enforcing, and the next start adopts it. `shukrad -detach-all` lifts it with the daemon down.
- **What the record says is what the kernel is made to do**, every two seconds, after a VM comes back with a new tap and after a restart. One difference is reported (in `policy` and the doctor), not hidden.
- **A tap enforcing a policy nobody recorded is an orphan** (the record was lost, or something else set it). The daemon does not guess about it: it is shown in `policy`, `doctor` warns, and `shukractl policy remove <vm>` puts the tap right whether or not there was a record. A policy file that cannot be read is set aside as `policies.json.corrupt` and the taps it named show up as orphans.
- **Isolation still wins, and does not disturb the policy.** An isolated VM is dropped as always; releasing it leaves its policy as it was.
- **It is announced.** Applying, confirming, reverting and removing a policy each raise a detection (`policy-applied`, `policy-confirmed`, `policy-reverted`, `policy-removed`), so a webhook hears of a change to what a VM may do.

## What it does not do

- **It is not a firewall.** It decides where a VM may *start* connections. ICMP is not judged, and a guest that sends TCP segments that are not a SYN, or crafts packets, is not stopped by it: a connection cannot be *established* without a SYN, which is what it judges.
- **Networks only.** No ports, no names. The baselines it learns from are IPv4 /24 and IPv6 /64 networks, so a proposal is as coarse as that. (Policy by server name, from [TLS server names](tap.md#tls-server-names), is not part of this.)
- **A UDP stream a guest sends to a peer that has gone quiet for a minute is judged** as a new flow. A peer's every datagram to the guest renews the minute.
- **A new tap has no policy for up to two seconds.** A VM that comes back with a new tap (a restart, a migration) is put back under its policy on the daemon's next pass, and until then the new tap is open. Enforcement across a daemon restart has no such gap: the maps are pinned.
- **DNS and DHCP need to be on the list.** A resolver the VM uses is a destination like any other, so it has to be listed or lookups stop; the baseline learns it because the flow to it was seen. DHCP discovery is broadcast and is not judged, but a renewal sent straight to the DHCP server is.
- **Up to 1,024 networks per VM**, and 16,384 across all VMs (the kernel map).
- IPv6 extension headers and VLAN tags are not looked through, as for everything the tap program does.

## Reading it

```text
$ shukractl policy
EGRESS POLICY  2 VMs
  web  enforce  12 networks (baseline), set by alice at 2026-09-20T03:00:00Z
      UNCONFIRMED: goes back to audit with 12 networks at 2026-09-20T03:10:00Z unless confirmed: shukractl policy confirm web
      vnet3  kernel enforce  judged 4210 new connections, 14 dropped (1400 bytes)
  db  audit  3 networks (manual), set by bob at 2026-09-19T14:00:00Z
      vnet6  kernel audit  judged 88 new connections, 7 would have been dropped (700 bytes)
```

- **`judged`** is every new connection or datagram the policy looked at, so it is the denominator: 14 dropped of 4210 is a policy that is nearly right.
- **`kernel`** is the mode the tap program is in, which is the policy's unless something is wrong; a difference is `PROBLEM` and a doctor warning.
- **`/metrics`** has `shukra_egress_policy_mode{vm,tap}` (0, 1, 2), `shukra_egress_policy_unconfirmed{vm}`, `shukra_egress_checked_total`, `shukra_egress_audit_packets_total`, `shukra_egress_audit_bytes_total`, `shukra_egress_dropped_packets_total` and `shukra_egress_dropped_bytes_total`, only for a VM that has a policy. Alert on `shukra_egress_policy_unconfirmed == 1` for longer than you would like a VM to hold a timer.
- **A drop is Shukra's own.** Policy drops are counted in the tap's `droppedPackets` and in the connect outcomes as *blocked*, like isolation's, so the [drops](drops.md) accounting does not blame someone else for them.

## API

| Route | |
|---|---|
| `GET /api/v1/policy[?vm=]` | Every policy (`mode`, `allow`, `source`, `by`, `applied`, `present`, `revert`, and per tap the kernel mode and counters), the orphans, and whether records are kept across a restart |
| `GET /api/v1/policy/proposal?vm=` | What the baseline proposes, and how it differs from the VM's current policy (`added`, `removed`) |
| `POST /api/v1/policy/apply` | Admin key. `{"vm", "mode", "allow"?, "fromBaseline"?, "confirm"?, "permanent"?}` |
| `POST /api/v1/policy/confirm`, `.../remove` | Admin key. `{"vm"}` |

A failure is `400` for a request that is wrong, `404` for a VM or policy that is not there and `409` for one that is refused (with the reason), each with the reason as text.

## Files

`policies.json` under `-data-dir` (mode 0600) holds every policy. It is rewritten whole, atomically and synced, on every change. It names VMs and the networks each may reach, so it is as sensitive as `baselines.json`.

## Cost

With no policy on a tap, the program does one extra read and compare per packet, about **7 to 10 ns** on the reference host (a data segment 76 to 78 ns before, 86 to 87 ns after), which is about 1% of a core at a million packets a second. A tap under a policy adds a trie lookup per new connection or datagram, and a flow-table update per datagram sent to the guest. Measured with [`scripts/bench-tap.sh`](../scripts/bench-tap.sh); see [testing](testing.md).
