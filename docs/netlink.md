# Netlink control-plane events

Shukra listens to the kernel's routing Netlink multicast groups and records link, address, route and neighbor changes. A VM that suddenly cannot reach its network is often one of those changes on the host: a bridge went down, an address moved, a default route was deleted. The event list has the change, with the time, without polling `ip` output.

This is not a BPF program. It is a Netlink socket in the daemon. Link notifications also refresh VM and tap discovery, which they already did; the events are the new part. See [guest traffic](tap.md) for how a new tap is attached from that refresh.

## Events

| Kind | Kernel notifications | Important fields |
| --- | --- | --- |
| `netlink_link` | `RTM_NEWLINK`, `RTM_DELLINK` | interface, ifindex, parent and master, MTU, operational state, flags |
| `netlink_address` | `RTM_NEWADDR`, `RTM_DELADDR` | interface, family, address, prefix length, scope |
| `netlink_route` | `RTM_NEWROUTE`, `RTM_DELROUTE` | destination, gateway, output interface, table, priority |
| `netlink_neighbor` | `RTM_NEWNEIGH`, `RTM_DELNEIGH` | peer address, link-layer address, NUD state |
| `netlink_error` | receive overrun or a Netlink error | signed kernel error code (`ENOBUFS` is `-105`) |

Every event has `attribution: "host-netlink"` and `guest_attributed: false`. It is a host control-plane observation, not evidence that a guest or QEMU changed the object. When the interface is a tap the current scan assigns to a VM, the event names that VM and is stored on that VM's flight recorder. A host interface (a bridge, a bond, a dummy) names no VM and goes to the `_host` recorder. Naming the VM does not mean the guest made the change: `guest_attributed` stays false either way. The detail is under `netlink` in the JSON. `shukractl watch` prints `action=`, `object=`, and whichever of `interface`, `address`, `destination`, `gateway`, `state` and `oper_state` the notification carried:

```text
2026-09-21T14:33:01Z  netlink_address  host-netlink  vm=  action=new  object=address  interface=br0  address=192.0.2.77
2026-09-21T14:33:01Z  netlink_route  host-netlink  vm=  action=delete  object=route  interface=br0  destination=0.0.0.0/0  gateway=192.0.2.1
```

Example:

```json
{
  "product": "shukra",
  "kind": "netlink_route",
  "attribution": "host-netlink",
  "guest_attributed": false,
  "netlink": {
    "action": "delete",
    "object": "route",
    "family": "ipv4",
    "interface": "br0",
    "ifindex": 4,
    "destination": "0.0.0.0/0",
    "gateway": "192.0.2.1",
    "table": 254
  }
}
```

They share the event list's host-network class with `tcp_connect` and `tcp_retransmit` (512 of the 2048 slots once the list is full). A burst of route updates can push older host connects out of that share; it cannot push out a guest event, a detection or a tripwire.

## What becomes a detection

The raw event is always stored. A detection is raised only for a change that can explain a loss of connectivity, and it keeps `attribution: "host-netlink"`. There is nothing to configure. Repeats of the same finding are suppressed with the other detections.

| Rule | Severity | Raised when |
| --- | --- | --- |
| `tap-link-deleted` | high | A VM's tap was deleted |
| `tap-link-down` | high | A VM's tap went `down` or `lower-layer-down` |
| `tap-master-changed` | high | A VM's tap moved to a different master, after Shukra had already seen it |
| `tap-mtu-changed` | medium | A VM's tap MTU changed, after Shukra had already seen a non-zero MTU |
| `tap-address-removed` | medium | An address was removed from a VM's tap |
| `default-route-removed` | high | The kernel deleted an IPv4 `0.0.0.0/0` or IPv6 `::/0` route, on any interface |
| `neighbor-failed` | medium | Neighbor resolution failed, on any interface |
| `netlink-overrun` | high | The socket lost messages or the kernel returned an error (`netlink-error`) |

A link, address or MTU change on an interface no VM owns is recorded and is not a detection. The first time Shukra sees a tap it does not call that an MTU or master change. `-netlink-events=false` stops both the events and these detections. The tap refresh still runs. `default-route-removed`, `neighbor-failed` and `netlink-overrun` name no VM, so a [response](responses.md) will not answer them. The tap findings name the VM, and a response can.

## What the socket accepts

The groups are link, neighbor, IPv4 and IPv6 addresses, and IPv4 and IPv6 routes. A message is kept only when the sender PID is zero, which is the kernel. Userspace Netlink is ignored. The receive buffer is 1 MiB. If the kernel drops messages because that buffer overran (`ENOBUFS`), that is a `netlink_error` and the listener keeps going. Link notifications are debounced by 50 ms before the tap refresh, so a burst is one scan.

`shukrad -netlink-events=false` stops recording these events. The socket stays open and a link change still refreshes tap discovery. The flag is on by default. `doctor` does not report it: turning the events off does not detach a program.

The listener runs in the daemon's network namespace. A change inside another namespace is not seen. It stops when the daemon's context is cancelled.
