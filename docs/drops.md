# Where packets die (the drops program)

When a VM's traffic goes missing, the question is not "is the network up" but "who threw the packet away". Shukra's own isolation, and an enforcing [egress policy](egress-policy.md), are two things that drop a VM's traffic. Cilium, a network dataplane, a `tc` filter, a firewall, and a guest that is not reading its NIC are others. The `drops` program answers with the kernel's own record, per VM tap, and tells Shukra's drops apart from everyone else's.

```text
$ shukractl trace drops
TRACE DROPS
  vm=chrome-e2e-vm  tap=vnet0  kernel=42  shukra=0  other=0  guest_not_reading=42
      FULL_RING      42  freed in tun_net_xmit
  vm=osboxes-mint   tap=vnet1  kernel=0   shukra=0  other=0  guest_not_reading=0
```

That is real output from a hypervisor (the command also prints a one-line note above `TRACE DROPS`, left out here). `chrome-e2e-vm` is losing every packet the host sends it, none of it Shukra's doing, because its guest never reads its NIC and the tun queue is full. Nothing else in the stack said so.

## What it measures

The kernel calls `kfree_skb` for every packet it throws away and records why, as a numbered reason from its `skb_drop_reason` list. The `drops` program hooks that tracepoint (`skb:kfree_skb`) and, for each packet dropped on a **VM tap**, counts it by reason and remembers which kernel function freed it. Every other packet the host drops costs one failed map lookup and is ignored.

- **The reasons are the kernel's, by name.** The numbers differ between kernels, so Shukra reads the names from the running kernel's BTF and never hardcodes them. A reason it cannot name is shown as `reason N`, not guessed.
- **The function is named by the kernel too.** The program asks the kernel to resolve the address (`bpf_snprintf` with `%ps`, once when a reason is first seen on a tap), so it needs no `CAP_SYSLOG` and no `/proc/kallsyms`. It is the function at the first free seen for that reason; if the kernel cannot name it, the address is shown.
- **It reads the record by field name.** Linux 6.9 added a field to `kfree_skb` and moved the others. The program takes the record's type from the kernel's own BTF (CO-RE), so it works on either layout.

## Whose drops are they

Shukra drops packets with the TCX program on the tap, for isolation and for an enforcing egress policy alike, and the kernel counts those as `TC_INGRESS` (from the guest) or `TC_EGRESS` (to the guest). So for each tap:

```text
kernel        every packet the kernel dropped on the tap, all reasons
shukra        what the tap program says it dropped (isolation, or an enforcing egress policy)
guest_not_reading   the FULL_RING drops: the tap's queue was full
other         kernel - shukra - guest_not_reading: something else dropped these
```

Both sides are counted **from when the daemon started**. The tap program's own counters are pinned and survive a restart, but the kernel's drop counts start again from zero, so the daemon remembers what the tap program had already dropped when it first looked and subtracts only what happened since. Without that, isolation from before a restart would hide another program's drops. A tap that is detached and attached again starts over. A daemon started while a VM is already isolated or under an enforcing policy therefore reads `shukra=0` until the tap drops something new: that is the baseline being taken, not a sign nothing was dropped.

`shukra` can explain at most as many packets as the kernel counted as `TC_INGRESS`/`TC_EGRESS`, so a bad guess cannot hide real drops. `other` above zero means another program on the tap, or another layer, is dropping the VM's traffic.

Fewer than 5 unexplained packets is treated as noise, by the doctor and by `explain` (both read the last minute, and say so): the tap program's counters and the kernel's are read a moment apart, so a small difference is skew between two reads. `trace drops` and the API show the raw numbers, so `other=3` there is not a finding.

## Reading the reasons

| Reason | What it means | Look at |
|---|---|---|
| `TC_INGRESS` | A tc or TCX program on the tap dropped a frame **from the guest**. If `shukra` accounts for it, that was isolation | `bpftool net show dev <tap>`: another program (Cilium, fluxvm's `fluxvm_egress`, a `tc filter`) is attached |
| `TC_EGRESS` | The same, for a frame sent **to** the guest | the same |
| `FULL_RING` | The tap's queue is full, so the host cannot hand the guest a packet. The guest is stalled, has no working network driver, or is overloaded | the VM itself. The kernel's `tx_dropped` on the tap climbs with it |
| `NETFILTER_DROP` | iptables or nftables | `iptables -L -v -n -x`: the rule whose packet counter is moving |
| `QDISC_DROP`, `CPU_BACKLOG` | The host's own queues are overflowing | host load and qdisc settings |
| `TAP_FILTER`, `TAP_TXFILTER` | A filter attached to the tap device itself | the process that opened the tap |
| `NOT_SPECIFIED`, `NO_SOCKET`, `IP_*`, `TCP_*` | A protocol layer rejected it | the protocol, not the link |

The full list is `skb_drop_reason` in the kernel; `shukractl trace drops` prints whatever this kernel calls each one.

## Where it shows

| Surface | What |
|---|---|
| `shukractl trace drops` | Per tap, then per reason with the function that freed the packets |
| `GET /api/v1/trace/drops[?vm=]` | `measured`, `taps` (per tap: `kernelDrops`, `shukraDropped`, `otherDrops`, `guestNotReading`, `reasons`) and `rows` (per reason: `reason`, `count`, `location`) ([API](api.md)) |
| `shukra_tap_kernel_drops_total{vm,tap,reason}` | A counter, only while the program is measuring. The Shukra/other split is on the API, not here, because it is a difference of two counters read a moment apart and can dip |
| `shukractl doctor` | `vm-drops-not-shukra` (warn) names the VM, the tap and the reason. `vm-nic-not-consumed` (warn) names a guest that is not reading its NIC |
| `shukractl explain <vm>` | `guest_traffic_dropped` and `guest_not_reading_nic`, over the last minute and not the life of the daemon |
| A `guest_drops_per_sec` rule | Alerts when the kernel drops packets on a VM's tap that Shukra did not, other than a full queue (that is `guest_not_reading`, and has no rule of its own). See [detection rules](tutorials/06-watchlist.md) |
| Console, Drops page | The same tables, with a "not measuring" message where the program is off |

Nothing is said while the program is not attached, and no series exists: a VM the program cannot see gets no zero.

## How do I know it works

```bash
shukractl programs            # drops  attached
shukractl trace drops         # one row per VM tap, with kernel=0 for a tap that has lost nothing
curl -s -H "Authorization: Bearer $SHUKRA_API_KEY" http://127.0.0.1:30970/metrics | grep shukra_tap_kernel_drops_total
```

A tap with no drops has a row of zeros (as `osboxes-mint` above): the row proves the tap is watched and that a zero is a measurement. A tap with no row at all is not watched: see the next section. `shukra_tap_kernel_drops_total` only has a series for a reason that has happened, so an empty result on a healthy host is normal.

Two checks on a VM you can afford to disturb, one for each side of the split:

- **Shukra's own drops are not blamed on anyone.** `shukractl isolate <vm>`, send some traffic from the guest, `shukractl release <vm>`. `kernel` and `shukra` rise together and `other` stays at 0. The same holds for an enforcing egress policy.
- **Someone else's are.** Put a real drop on the tap, send traffic, then take it off:

```bash
sudo tc qdisc add dev <tap> clsact
sudo tc filter add dev <tap> ingress matchall action drop     # drops everything the guest sends
sudo tc filter del dev <tap> ingress                          # undo
```

`TC_INGRESS` rises in `trace drops`, `shukra` does not, and `other` does. This is what the tap rig does with a real `tc` filter; see [How it was checked](#how-it-was-checked).

For a guest that is not reading its NIC the check is the kernel's own counter: over any window, `FULL_RING` should rise by the same amount as `tx_dropped` in `ip -s link show <tap>` (it did, exactly, on all nine taps of the reference host).

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `drops  detached  this kernel's skb:kfree_skb has no drop reason (it needs Linux 5.17 or newer)` | The kernel is too old for a drop reason. The rest of Shukra works | Upgrade, or use the `bpftrace` one-liner [below](#without-the-program) |
| `drops  detached  skb:kfree_skb is not readable` or `has no readable format` | Tracefs is not mounted where the daemon looks (`/sys/kernel/tracing`, then `/sys/kernel/debug/tracing`), or it is not readable | Mount tracefs. The program does not attach at all when it cannot check the record's layout, because reading a moved field would count nonsense |
| `shukractl trace drops` says `the drops program is not measuring` | The program is detached | `shukractl programs` gives the reason. The API says `"measured": false`, and there is no `shukra_tap_kernel_drops_total` |
| `no VM tap has been seen yet` | The program is attached but no VM has a tap Shukra is on | See [tap troubleshooting](tap.md#troubleshooting) |
| A VM has no row | Its tap is not one the tap program is on: user-mode networking, or a tap the scan could not map. Doctor names it (`blind-vms`, `vm-tap-other-netns`) | Fix that first: drops follow the tap program's interfaces |
| A reason shown as `reason 95` | This kernel's reason names could not be read from BTF, or the reason is newer than the names | The number is the kernel's. Look it up in `skb_drop_reason` for your kernel |
| `other` is above 0 and nothing else seems attached | Something else drops on the tap, or on a layer below it | `bpftool net show dev <tap>`, then the reason table above |
| `other` is 1 to 4 | Skew between two reads | Nothing. The doctor and `explain` ignore fewer than 5 |
| `shukra=0` after a daemon restart on an isolated VM | Both sides count from the daemon's start | Wait for new traffic; see [Whose drops are they](#whose-drops-are-they) |
| The function is an address such as `0xffffffff8a4b1c20` | The kernel could not name it | The address is still the kernel's. `/proc/kallsyms` needs `CAP_SYSLOG` to show real addresses |
| A `guest_drops_per_sec` rule never fires while a guest is not reading its NIC | That rule excludes a full queue | `guest_not_reading` and the doctor's `vm-nic-not-consumed` cover it |

## Limits

| What | Limit |
|---|---|
| Taps watched | 1,024 (the watch list) |
| Distinct (tap, reason) pairs | 4,096 (`drop_stats`, summed over CPUs when read). A tap has a handful of reasons in practice |
| Function name | 48 characters, as the kernel names it. Resolved once, at the first free seen for that tap and reason |
| Kernel | Linux 5.17 or newer, for a drop reason on `skb:kfree_skb` |
| History | None. The counts are the daemon's own since it started; `explain` and the doctor look at the last minute. The program's maps are not pinned |
| Cost | About 255 ns per drop on any interface, and one failed lookup for a packet that is not on a VM tap (see [Cost](#cost)) |

## What it does not do

- It counts packets the **host kernel** dropped on the tap. A drop inside the guest, or on the physical network, is not seen.
- It needs Linux 5.17 or newer, for the drop reason. On an older kernel it reports itself `detached` with that reason and the rest of Shukra works.
- It watches the interfaces the tap program is on, so a VM with no host interface (user-mode networking, or a tap the scan could not map out of another namespace) has no drops row. `shukractl doctor` names those VMs. A FluxVM guest on the default netns is watched on its host veth. See [FluxVM](tap.md#fluxvm).
- The function is the first free seen for a reason on a tap. If the same reason is later freed somewhere else, that is not shown.

## Cost

It runs once for every packet the host drops anywhere, and returns after one map lookup unless the packet was on a VM tap. Measured on a 12-CPU Xeon hypervisor: **69 runs a second at about 255 ns each, which is 0.002% of one CPU.** Scale by your own drop rate: at a million drops a second it would cost about a quarter of a CPU. `bpftool prog show name drops_kfree_skb` reports `run_time_ns` and `run_cnt` while any process has run-time stats enabled.

## Without the program

The kernel will still say where. Trace the drops by hand while the traffic runs:

```bash
sudo bpftrace -e 'tracepoint:skb:kfree_skb /args->protocol == 0x800/ {
  $skb = (struct sk_buff *)args->skbaddr;
  $dev = $skb->dev->name;
  @[args->reason, ksym(args->location), $dev] = count(); }'
```

The reason prints as a number; the names are in `/sys/kernel/tracing/events/skb/kfree_skb/format`.

## What a real host showed

Everything above was found on a real hypervisor, not designed in advance:

- **Guests that never read their NIC.** Four libvirt guests showed `FULL_RING`, freed in `tun_net_xmit`, and the kernel's own `tx_dropped` on their taps rose by exactly the same number over any window (+30 in 60 seconds, on all four, and +0 on the rest).
- **Another program dropping guest traffic.** Two test guests' taps showed `TC_INGRESS` drops, freed in `__netif_receive_skb_core`, with Shukra's own count at 0. `bpftool net show dev <tap>` listed fluxvm's `fluxvm_egress` at `clsact/ingress`. That host's fluxvm dataplane was configured to allow only private CIDRs and ports 80, 443 and 53, so a guest's traffic to a public address, or to another guest on an unlisted port, was dropped at the sender's tap.
- **Two guests with the same MAC.** fluxvm gives a tap guest QEMU's default MAC unless the spec sets `mac`, so a second guest on the same bridge takes the first one's frames. Set a unique `mac` on each.
- **A tap in another network namespace.** On that host, FluxVM's default put each guest tap in its own namespace and Shukra attached nowhere, so `shukractl doctor` named the VM and there was no drops row. That default is now traced on the host veth `vh<8hex>`. A tap the scan still cannot map is named the same way. See [FluxVM](tap.md#fluxvm).

The handshake counts point the same way: on that run the guest under test made 31 outbound TCP attempts, 2 accepted, 2 refused and 27 never answered, while the taps showed 110 and 60 dropped packets. A packet count and a connection count are different units and do not match, but both are consistent with a dataplane dropping the guests' traffic to public addresses. That cause was inferred from the program attached to the taps, not proven by removing it. See [guest traffic](tap.md) for the handshake counters, and the [walkthrough](tutorials/08-lost-traffic.md) for how to use both together.

## How it was checked

- **On the real hypervisor:** the program loads and attaches (Linux 6.8), and over 60 seconds shukra's `FULL_RING` count equals the kernel's `tx_dropped` delta exactly on all nine taps.
- **On GitHub's newer kernel (6.9 or later):** the tap rig (`scripts/test-tap.sh`) drops real packets with a `tc` filter on the tap and checks they are counted as `TC_INGRESS` and as `other`, then isolates the VM and checks that Shukra's own drops are **not** blamed on anyone. The program first failed to attach there, because its hard-coded layout did not match a newer kernel (Linux 6.9 moved the fields), and it attached and passed once it read the record by field name.
- **Unit tests** cover the join, the subtraction, windows, counter resets, the doctor and Explain findings, the API, the metric and the threshold. Each goes red when its logic is removed.

## See also

[Guest traffic and isolation](tap.md), whose counters this program is read against (`dropped`, the handshake outcomes, `to_guest`). [Egress policy](egress-policy.md), whose drops count as Shukra's own. [Doctor](doctor.md), for the three findings built on these counts. The [walkthrough](tutorials/08-lost-traffic.md) follows them from symptom to cause.
