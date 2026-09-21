# Learn, audit, enforce an egress policy

You want a VM to start connections only to the networks it normally talks to. Writing that list by hand is how a working VM gets cut off, so Shukra makes you go in three stages, each one safer than the next is risky:

1. **Learn.** The VM's [baseline](../baselines.md) records where it connects. `shukractl policy learn` turns that into a proposed list. Nothing changes.
2. **Audit.** The VM is put under the list, but nothing is dropped. What *would* have been dropped is counted and reported, so you see what the list gets wrong while it still costs nothing.
3. **Enforce, with a timer.** Only then is traffic outside the list dropped, and unless a person confirms within the time you gave, the VM goes back to what it had.

A VM with no policy is untouched, and nothing here starts until you run `policy apply`. Reference: [egress policy](../egress-policy.md). This tutorial is the order to do it in and what you should see at each step.

Plan for the learning period plus a day or two of audit. The commands themselves take minutes.

## Before you start

You need:

- The **tap program** attached to the VM's tap (Linux 6.6+). `shukractl programs` says `tap  attached`, and `shukractl vms` shows a real interface in `taps=` for the VM, not `-`. A VM on user-mode networking has none, and `shukractl doctor` names it.
- `shukrad` running with `-data-dir` (the shipped unit does). Audit does not need it, but enforcing does, and so does keeping the learning.
- The **admin** key. `apply`, `confirm` and `remove` are POSTs, and a read-only key gets `403`.
- A VM you can afford to lose the network of for a few minutes, for the first time through. Use a test VM.
- A way onto the hypervisor that does not depend on that VM's network.

All the commands assume `SHUKRA_URL` and `SHUKRA_API_KEY` are set, as in [the CLI tutorial](04-shukractl.md). The VM below is `web-01`. Times are printed by the CLI with their fraction of a second; they are cut to the second here.

## 1. Let the VM's baseline learn

The baseline is off until the rules file has a `baselines:` section. Add this to `/etc/shukra/detections.yaml` (it is one more top-level section, next to what is already there):

```yaml
baselines:
  learn: 24h
```

Check it and load it:

```bash
shukractl rules check /etc/shukra/detections.yaml
sudo systemctl reload shukra
shukractl baseline
```

You should see each VM the daemon has watched and when its learning ends:

```text
BASELINE  learning period 24h0m0s, at most 20 new-item alerts per VM per day
  vm=web-01  learning until 2026-09-21T03:00:00Z  (destination 4, dns-suffix 2, inbound-peer 0)  new alerts today 0, held back in all 0
```

A VM appears once it has been seen. If it says `no VM has been observed yet`, wait a minute and ask again.

Two things to know before you trust what it learns:

- **Whatever the VM does now becomes normal.** A VM that is already misbehaving teaches the baseline that misbehaviour is fine. Start with a VM you trust.
- **It only learns what the VM does while it is watching.** A nightly backup target, a weekly patch mirror or a monthly report server appear only if the learning period is long enough to include them. Anything it misses will show up in the audit stage, which is what that stage is for.

See what it has learned so far:

```bash
shukractl baseline web-01 --items
```

Only the `destination` items (the /24 or /64 network the guest connected or sent to) go into a policy. The site names and inbound peers do not.

## 2. Ask for a proposal

```bash
shukractl policy learn web-01
```

This only reads. You do not have to wait for the learning period to end, and if it has not, the answer says so:

```text
POLICY PROPOSAL  web-01  4 networks  (still learning: it may be incomplete)
  the VM is still inside its baseline's learning period (until 2026-09-21T03:00:00Z): what it has not done yet is not on this list
    10.20.0.0/24
    192.0.2.0/24
    203.0.113.0/24
    2001:db8:1::/64
  audit it first: shukractl policy apply web-01 --mode audit --from-baseline
```

Read the list as the answer to "what does this VM need to reach": its DNS resolver, its time source, its package mirror, its database. A network you know it needs and do not see here is either still to come or was never learned. Add it later with `--allow`. The networks are as coarse as the baseline: an IPv4 `/24` or an IPv6 `/64`, so a proposal can allow more than the one address the VM actually used.

If you run `policy learn` again later for a VM that already has a policy, lines starting with `+` are networks the baseline has seen since that the policy does not list, and `-` are listed ones it has not seen. Read them before you apply: a baseline learns what the guest *attempted*, including a connection a policy dropped, so a VM that has been enforced for a while can propose networks it was never allowed to reach.

## 3. Audit

```bash
shukractl policy apply web-01 --mode audit --from-baseline
```

```text
web-01: egress policy applied
  web-01  audit  4 networks (baseline), set by shukractl at 2026-09-21T09:12:40Z
      vnet3  kernel audit  judged 0 new connections
```

Nothing is dropped, and audit needs no management allow list. The line to look at is `kernel audit` under each tap: the tap program is now in audit mode. If it said anything else there would be a `PROBLEM` line beneath it, and `shukractl doctor` would warn.

What the policy judges is what the guest *starts*: a TCP SYN, or a UDP datagram that is not multicast and not an answer. It does not judge a server answering a client that connected in, so a VM that serves things keeps working under enforcement too.

## 4. Read what the audit says

Give it a day or two, then:

```bash
shukractl policy web-01
```

```text
EGRESS POLICY  1 VMs
  web-01  audit  4 networks (baseline), set by shukractl at 2026-09-21T09:12:40Z
      vnet3  kernel audit  judged 4210 new connections, 7 would have been dropped (700 bytes)
```

`judged` is every new connection or datagram the policy looked at, so it is the denominator: 7 of 4210 is a list that is nearly right. The counts are of packets, so a guest that retries one blocked SYN counts each try.

To see *where* those would have gone:

```bash
shukractl security web-01
shukractl watch --json --once | grep egress-policy-audit
```

```text
  low  10.30.0.5  web-01 opened tcp to 10.30.0.5:5432, outside its egress policy: it would have been dropped (audit mode)  guest_attributed=true  attribution=guest-tap
  low  198.51.100.7  web-01 opened tcp to 198.51.100.7:80, outside its egress policy: it would have been dropped (audit mode)  guest_attributed=true  attribution=guest-tap
```

The first is a database network the baseline never saw (a monthly job, say). The second is the deliberate stray from below.

Each is a low `egress-policy-audit` detection, and the guest's event itself carries `"policy":"audit"`. They are held back per VM, `/24` or `/64` network and protocol for the rules file's `suppress` time (five minutes by default), so a VM that keeps trying one place is one detection while the counters count all of it.

The same counts are on `/metrics`:

```bash
curl -s -H "Authorization: Bearer $SHUKRA_API_KEY" "$SHUKRA_URL/metrics" | grep shukra_egress
```

You want `shukra_egress_policy_mode{vm="web-01",tap="vnet3"} 1` (audit), `shukra_egress_checked_total` and `shukra_egress_audit_packets_total`.

To see a hit on purpose (the second line above), from inside the guest open a connection to a documentation-range address, which is on no list and goes nowhere: `curl -m 3 http://198.51.100.7/`. Under audit it is sent as always and shows up here. Under enforcement it is dropped and never answered.

### Fix the list

Look at every network the audit flagged and decide: is this something the VM should do? The database network above is; the stray is not. Add what belongs. `--allow` **replaces** the whole list, so give the current list plus the new network. `jq` is convenient for the current list:

```bash
shukractl policy web-01 --json | jq -r '.policies[0].allow | join(",")'
shukractl policy apply web-01 --mode audit --allow 10.20.0.0/24,10.30.0.0/24,192.0.2.0/24,203.0.113.0/24,2001:db8:1::/64
```

A bare address is a `/32` (or `/128`), and host bits are cleared, so `10.1.2.3/24` is `10.1.2.0/24`. The list is now `manual` in the `(...)` of the policy row instead of `baseline`.

Repeat until a few days go by and the audit only flags things you would want blocked. Audit costs a counter per packet and nothing else. There is no hurry.

## 5. Give enforcement its floor: the management allow list

Enforcing is refused until the daemon knows the **management allow list**, the networks a VM must always be able to reach and be reached from. The policy never judges those, whatever it says: it is the floor, so a wrong policy cannot cut a VM off from the network that manages it. It is the same list isolate uses (`-isolate-allow`).

> **Before you turn this on.** A management allow list enables *isolate* and *enforce*, which means anyone holding the admin key can now cut a VM off. The shipped unit listens on `127.0.0.1:30970`. If `shukractl doctor` reports `The API key is the well-known dev key` or `The API is plain HTTP on a non-loopback address`, fix that first: a real key in `/etc/shukra/env`, and TLS in front of loopback rather than `-allow-insecure-http` ([deploy](03-deploy.md#encrypt-the-api)). The dev key is only what a binary uses when `SHUKRA_API_KEY` is unset; a packaged install generates a random key. Do not add an allow list to a host that still has the dev key or cleartext HTTP off loopback.

Put the flag on the one `SHUKRA_EXTRA_ARGS=` line in `/etc/shukra/env`. There must be only one such line: if a second is added, the last one wins and the first is lost, which would drop a TLS setting.

```bash
sudo grep '^SHUKRA_EXTRA_ARGS=' /etc/shukra/env          # what is there now
sudoedit /etc/shukra/env                                  # e.g. SHUKRA_EXTRA_ARGS=-isolate-allow 10.0.0.0/24
sudo systemctl restart shukra
```

Use the networks your operators and monitoring come from, and the gateway they sit behind. Then check:

```bash
shukractl security web-01
```

```text
SECURITY  web-01  enforcement=tcx
  management allow list: 10.0.0.0/24
```

`enforcement=tcx` means enforcing is available. `shukractl doctor` also stops saying `Isolate is not enabled`. A restart is safe for policies: the record is on disk, and the daemon puts each policy back on its tap as it starts. A tap with only an audit policy is detached on a graceful stop, so its audit counters may start again from zero.

Without the list, this is what you get, and nothing was changed:

```text
error: POST /api/v1/policy/apply: refused: enforcing needs the management allow list (-isolate-allow), the floor that no policy can take away: no management allow list is configured (-isolate-allow), so refusing to isolate: an isolated VM must keep the access its host needs
```

## 6. Enforce for thirty seconds, and let it go back

Rehearse the way back before you depend on it. Thirty seconds is the shortest time allowed:

```bash
shukractl policy apply web-01 --mode enforce --confirm 30s
```

```text
web-01: egress policy applied
  web-01  enforce  5 networks (manual), set by shukractl at 2026-09-22T09:00:12Z
      UNCONFIRMED: goes back to audit with 5 networks at 2026-09-22T09:00:42Z unless confirmed: shukractl policy confirm web-01
      vnet3  kernel enforce  judged 4210 new connections, 7 would have been dropped (700 bytes)
```

`UNCONFIRMED` names what it will go back to and when. Do not confirm. In the meantime `shukractl doctor` warns `1 enforcing egress policies are waiting to be confirmed`, and a `policy-applied` detection (medium) has gone to your sinks. After the time is up, and the daemon's two-second pass has run:

```bash
shukractl policy web-01
```

```text
EGRESS POLICY  1 VMs
  web-01  audit  5 networks (manual), set by shukractl at 2026-09-22T09:00:44Z
      vnet3  kernel audit  judged 4212 new connections, 7 would have been dropped (700 bytes)
```

It is back in audit, the `UNCONFIRMED` line is gone, and a medium `policy-reverted` detection says so: *web-01's enforcing egress policy was not confirmed in time and has gone back to audit with 5 networks*. If the VM had no policy before, the revert removes it instead. Changing an unconfirmed policy does not move where it goes back to: it is still what the VM had before all of it.

Two things about the timer:

- **It is the daemon's.** The record of the timer is saved before the kernel changes, and a daemon that was down when the time ran out reverts the VM on its first pass after it starts. But while the daemon is down the kernel keeps enforcing (the policy lives in pinned maps, like isolation), so a VM stays cut off from anything outside its list until the daemon is back, or until you lift it without the daemon ([below](#lifting-it-without-the-daemon)).
- **A revert is not an undo of what was dropped.** Connections the policy dropped while it was on stay dropped.

## 7. Enforce, check the VM, confirm

```bash
shukractl policy apply web-01 --mode enforce --confirm 5m
```

`apply` with no list keeps the VM's current one, so this does not repeat `--from-baseline` or `--allow`. Use `--permanent` instead of `--confirm` only once you have done this before, and never for a first time.

Now use the VM the way it is used: reach its service from a client, log in, let a job run. Its own clients keep working, because a server answering is not judged. What stops is the VM *starting* something outside the list. The stray from step 4 now gets no answer:

```bash
shukractl trace tap --vm web-01
```

```text
  tap=vnet3  from_guest=... dropped=3 pkts  isolated=false
      connects out: 31 attempts = 28 accepted + 0 refused + 0 never answered + 3 blocked  (0 retransmits, handshake p50 262144ns p99 524288ns)
```

`blocked` is what Shukra dropped (the same word isolation uses), and a medium `egress-policy-blocked` detection names each place: *web-01 opened tcp to 198.51.100.7:80, outside its egress policy: it was dropped*. Because the drop is Shukra's own, [where packets die](../drops.md) does not blame anyone else for it, and [tutorial 8](08-lost-traffic.md) reads it as `blocked`.

If the VM is working and you are still inside the time:

```bash
shukractl policy confirm web-01
```

```text
web-01: egress policy confirmed
  web-01  enforce  5 networks (manual), set by shukractl at 2026-09-22T09:05:31Z
      vnet3  kernel enforce  judged 4380 new connections, 7 would have been dropped (700 bytes), 12 dropped (1200 bytes)
```

The timer is gone, the policy stays, and a low `policy-confirmed` detection says who confirmed it. The console's **Egress policy** page (`#page=policy`) does the same with Confirm and Remove buttons and lists a policy waiting for a decision first.

If the VM is not well, do nothing: it goes back at the time shown. To go back at once, `shukractl policy apply web-01 --mode audit` (audit needs no confirmation) or `shukractl policy remove web-01`.

## 8. Remove it

```bash
shukractl policy remove web-01
```

```text
web-01: the egress policy is removed. Nothing is judged on its taps now.
```

The kernel is put right first and the record deleted after, so a failure to save the record never leaves a VM held by a policy nobody can see. `policy-removed` (low) is raised. `--mode off` on `apply` does the same.

Isolation and policy do not disturb each other. An isolated VM is dropped as always, and releasing it leaves its policy as it was.

## Orphans, and what the doctor says

The kernel enforces from pinned maps, so it can outlive the daemon's record of a policy: the record was lost, or something else set it. A tap in that state is an **orphan**. The daemon does not guess about it. It shows it:

```text
EGRESS POLICY  0 VMs
  none. shukractl policy learn <vm> proposes one from what the VM has been seen to do; audit it before enforcing
  ORPHAN  web-01 (vnet3) is enforce: the kernel applies a policy nobody has a record of. shukractl policy remove web-01
```

and `shukractl doctor` warns:

```text
[warn] 1 taps apply an egress policy that nobody has a record of
       The kernel is applying it, so it is dropping or auditing whatever it lists, and the daemon cannot say what that is or ever revert it: web-01 (vnet3, enforce). The record was lost, or something else set it.
       fix: shukractl policy remove web-01 lifts it and puts the tap right, and a new one can be applied after.
```

`policy remove` works whether or not a record exists. A `policies.json` that cannot be read is set aside as `policies.json.corrupt` under `-data-dir`, and the taps it named appear as orphans.

The other doctor finding is `The kernel is not doing what an egress policy says`: a tap is in a different mode than the record. The daemon puts it right every two seconds, so it only stays if the tap program failed to take the list (see the daemon's log).

### Lifting it without the daemon

`shukrad -detach-all -data-dir /var/lib/shukra` removes every pinned tap link and map on the host. That lifts every enforcing policy **and every isolation**, for every VM, so use it only when the daemon cannot run. It records a release for isolations but does not edit the record of policies, and a restarted daemon puts a recorded policy back in the kernel. So, once the daemon is running again, run `shukractl policy remove <vm>` for each VM that had one (or, to end every policy at once, move `policies.json` aside in `-data-dir` before you start the daemon again).

## Keep an eye on it

Alert on a policy nobody confirmed. On `/metrics`, `shukra_egress_policy_unconfirmed == 1` for longer than you want a VM to hold a timer. `policy-applied`, `policy-confirmed`, `policy-reverted` and `policy-removed` are detections, so they go to every [alert sink](07-alert-sinks.md) and a webhook hears of a change to what a VM may do.

> **If it does not work.** The refusals name their cause:
>
> | You see | Do this |
> |---|---|
> | `refused: enforcing needs the management allow list (-isolate-allow)` | Step 5, with its warning |
> | `refused: enforcing needs -data-dir` | The shipped unit has it. For a hand-run daemon add `-data-dir /var/lib/shukra`. `shukractl policy` says `(audit only: ...)` in this case |
> | `bad request: enforcing needs --confirm <duration> ... or --permanent` | Give `--confirm 5m` (30 seconds to 24 hours) |
> | `refused: an empty list would cut the VM off ...` | Give a list. Cutting a VM off from everything is `isolate` |
> | `not found: no VM named "web-01" is in the current scan` | Use the name `shukractl vms` prints. A stopped VM cannot be given a policy |
> | `refused: web-01 has no tap interface` | The VM is on user-mode networking, or its tap could not be read. `shukractl doctor` says which |
> | `refused: the tap program is not loaded` | `shukractl programs`: the tap program needs Linux 6.6+ and a build with BPF |
> | `bad request: no list of networks` | Give `--allow` or `--from-baseline`. Only a VM that already has a policy can be applied again with no list |
> | `refused: learned baselines are off` | Step 1, or give the networks with `--allow` |
> | `not found: the baseline has not seen a VM named ...` | The VM has not connected anywhere yet. Give it a minute of traffic |
> | `{"error":"this key is read-only"}` | You used the read-only key. `apply`, `confirm` and `remove` need the admin key |
>
> A proposal that says `the VM has not been seen connecting anywhere` is a VM with no traffic yet. A VM that broke under enforcement and did not come back on its own: `shukractl policy remove web-01`, and if the daemon is not answering, `shukrad -detach-all` (with the caution above).

## What a policy does not do

- **It is not a firewall.** It decides where a VM may *start* connections. ICMP, ARP and multicast are not judged, and packets that are not a SYN or a new UDP flow are not stopped by it. A connection cannot be established without a SYN, which is what it judges.
- **Networks only.** No ports and no names. The proposal is as coarse as the baseline's /24 and /64.
- **A new tap is open for up to two seconds.** A VM that comes back with a new tap (restart, migration) is put back under its policy on the next pass. Across a daemon restart there is no such gap, because the maps are pinned.
- **DNS and DHCP must be on the list.** A resolver the VM uses is a destination like any other. The baseline learns it because the flow was seen, but a resolver the VM has not used yet is not there.
- **Up to 1,024 networks per VM**, and 16,384 across all VMs for IPv4 and again for IPv6.

Full list and the API: [egress policy](../egress-policy.md). Next: [watch the VMM itself](11-vmm-tripwires.md).
