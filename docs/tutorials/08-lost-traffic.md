# Find out why a VM's traffic is lost

A VM "can't reach" something. Is the destination refusing it, is something on the host dropping it, is the guest not reading its NIC, or is it Shukra's own isolation or egress policy? This walkthrough asks the host four questions in order, using the guest's own tap as the witness, and does not touch the guest.

A sudden loss can also be the host's own network changing under the VM: a bridge, an address, a route or a neighbor. `shukractl watch` shows those as `netlink_*` events. A VM tap that went down or was deleted, a removed default route, or a failed neighbor is a detection as well (`tap-link-down`, `default-route-removed`, `neighbor-failed`). See [Netlink](../netlink.md).

It needs the `tap` program (Linux 6.6+) and, for the third step, the `drops` program (5.17+). `shukractl programs` says which are attached.

## 1. Start with what the daemon already noticed

```bash
shukractl doctor
```

Real output from a hypervisor:

```text
[warn] 4 VMs are not reading their NIC
       chrome-e2e-vm (vnet0: 33), converted-vm-2fae1d (vnet4: 33), ... packets were dropped over 1m7s because the tap's queue was full.
       fix: The guest is stalled, has no working network driver, or is overloaded. Look at the VM itself.
```

Doctor reads the last minute, not the life of the daemon, and only prints what needs attention. Three findings matter here:

| Finding | Means |
|---|---|
| `vm-nic-not-consumed` | The host has packets for the guest and the guest is not taking them. The problem is inside the VM |
| `vm-drops-not-shukra` | The kernel is dropping the VM's packets and it is not isolation. Something else is attached to the tap |
| `vm-connects-failing` | Most of the VM's outbound TCP connections were refused or never answered |

If one of those names your VM, jump to its step. If not, keep going.

## 2. Did the connection get an answer?

```bash
shukractl trace tap --vm web-01
```

An example. The outbound numbers are from a real test guest on a real hypervisor; the inbound line is illustrative:

```text
  tap=eph075a3816  from_guest=... dropped=0 pkts  isolated=false
      connects out: 31 attempts = 2 accepted + 2 refused + 27 never answered + 0 blocked  (4 retransmits, handshake p50 262144ns p99 524288ns)
      connects in:  4 attempts = 2 accepted + 1 refused + 1 ignored + 0 blocked  (0 retransmits)
```

Every outbound attempt is exactly one of the four, so read it as a table of what happened:

| You see | It means | So look at |
|---|---|---|
| Mostly **accepted** | The network works. The problem is above TCP: the service, TLS, DNS | the application |
| Mostly **refused** | The destination answered "nothing is listening" (an RST) | the destination's service and port. Many refusals to many ports looks like a scan |
| Mostly **never answered** | The SYN went out and nothing came back: something dropped it | step 3 |
| **blocked** | Shukra dropped it: the VM is isolated, or an enforcing [egress policy](10-egress-policy.md) does not list the destination | `shukractl policy <vm>` and `shukractl security <vm>` name which. Isolation: `shukractl release <vm>`. Policy: add the network, or `shukractl policy remove <vm>` |

Connections made **to** the guest are the `in` line. `ignored` is a SYN the guest never answered: a firewall inside the guest, or a service that is not running. `guest_inbound` events name each peer, and a `ports` rule with `dir: in` can alert on them.

The handshake time is the time from the guest's SYN to the answering SYN-ACK, both seen at the host's tap: the round trip to the destination plus how fast the destination answers. A p99 in seconds means the network or the destination is slow, not the guest.

## 3. Who dropped it?

```bash
shukractl trace drops --vm web-01
```

```text
  vm=web-01  tap=eph075a3816  kernel=110  shukra=0  other=110  guest_not_reading=0
      TC_INGRESS     110  freed in __netif_receive_skb_core
```

`kernel` is every packet the kernel dropped on the tap. `shukra` is what the tap program dropped (isolation, or an enforcing egress policy). `other` is the rest, so here **something other than Shukra dropped 110 packets**, and the reason says how:

- `TC_INGRESS` or `TC_EGRESS` with `other` above zero: another program on the tap dropped it. Name it:

  ```bash
  sudo bpftool net show dev eph075a3816
  ```

  ```text
  eph075a3816(2157) clsact/ingress fluxvm_egress:[*fsobj] id 21283
  ```

  That is fluxvm's dataplane. Its policy (`allow_cidrs`, `allow_ports`) is what dropped the guest's traffic to anywhere it does not list.
- `FULL_RING`: the guest is not reading its NIC (the same as `guest_not_reading`).
- `NETFILTER_DROP`: iptables or nftables. `iptables -L -v -n -x` shows the rule whose counter is moving.
- Anything else: see [the reasons](../drops.md#reading-the-reasons).

Cross-check the two views. They count different things: a connection that is never answered is one attempt, while the drops are packets, and each unanswered SYN, its retransmits and the guest's other traffic to the same place all count. So the numbers will not match, but the story should: many unanswered connections and many `other` drops on the same VM, with a program named by `bpftool`, is two independent programs describing one fault. On the test guests above, 27 unanswered connections came with 110 dropped packets, consistent with fluxvm's dataplane dropping their traffic to public addresses (that cause was inferred from the attached program, not proven by isolating it).

## 4. Ask Explain, over the last minute

```bash
shukractl explain web-01
```

`explain` weighs the host-side causes the counters support, best supported first, over the last minute. Drops and failing connections appear as `guest_traffic_dropped`, `guest_not_reading_nic` and `guest_connects_failing`, with evidence. The `missing` list says what Shukra cannot see (CPU steal, the process inside the guest): if the cause is there, this will say so and not guess.

## Keep watching

Alert instead of asking. In the detection file:

```yaml
thresholds:
  - name: vm-traffic-dropped
    metric: guest_drops_per_sec        # the kernel dropped VM packets that Shukra did not
    op: ">"
    value: 5
    window: 30s
    severity: high
  - name: vm-connects-failing
    metric: guest_connect_timeouts_per_sec
    op: ">"
    value: 2
    window: 30s
    severity: medium
ports:
  - port: 22
    name: ssh-into-vm
    dir: in                             # a connection made TO the VM, matched on the port it reached
    severity: medium
```

Validate before reloading: `shukractl rules check /etc/shukra/detections.yaml`, then `systemctl reload shukra`. See [detection rules](06-watchlist.md).

For a dashboard, the same facts are Prometheus series:

```promql
# refused connections per second, per VM
sum by (vm) (rate(shukra_tap_connect_outcomes_total{direction="out",result="refused"}[5m]))

# the share of a VM's connections that were never answered
sum by (vm) (rate(shukra_tap_connect_outcomes_total{direction="out",result="timed_out"}[5m]))
  / sum by (vm) (rate(shukra_tap_connect_attempts_total{direction="out"}[5m]))

# packets the kernel dropped on a VM's tap, by reason
sum by (vm, reason) (rate(shukra_tap_kernel_drops_total[5m]))

# how long the guest's connections take to be answered (p99)
histogram_quantile(0.99, sum by (le, vm) (rate(shukra_tap_handshake_seconds_bucket[5m])))
```

## Afterwards

If you are asked about it the next day, `shukractl explain <vm> --at ...` and `shukractl incident <vm> --at ... --out file` work from the daemon's stored snapshots: [investigate after the fact](09-after-the-fact.md).

## What this cannot tell you

- It sees the **host kernel's** view of the tap. A drop inside the guest, or on the physical network past the host, is not visible, and neither is which **process** in the guest made a connection.
- A server that answers after 3 seconds is counted as never answered, not accepted.
- A VM with no host interface Shukra can attach to (user-mode networking, or a tap the scan could not map out of another namespace) has none of this. `shukractl doctor` names those VMs. FluxVM's default netns is attached on the host veth; see [FluxVM](../tap.md#fluxvm).

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `trace tap` says `no rows`, or `doctor` lists the VM as having no tap | The VM has no interface Shukra can attach to (user-mode networking, or a tap it could not map). None of this walkthrough applies to it |
> | `trace drops` says `the drops program is not measuring` | The `drops` program is `detached`: `shukractl programs` says why (it needs Linux 5.17+). Steps 1, 2 and 4 still work |
> | `blocked` is not zero and you did not isolate the VM | An enforcing egress policy: `shukractl policy <vm>` |
> | `bpftool net show dev <tap>` lists only `shukra_tap` programs | Nothing else is attached to the tap. Read the reason in `trace drops` instead |

