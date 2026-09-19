# Guest traffic and isolation (the tap program)

Every other program in Shukra sees the QEMU process. This one sees the guest. It attaches TCX to the host side of each VM's tap interface, so a frame it counts really is the guest's, and events from it are the only ones Shukra marks `guest_attributed: true`.

## What it needs

- Linux 6.6 or newer, for TCX. Older kernels report the tap program as detached with `TCX needs Linux 6.6 or newer`. There is no TC fallback yet.
- A VM with a tap interface. The tap name comes from the QEMU command line (`ifname=tap0`, or libvirt's `vnet0`). A VM on user-mode networking has no tap, so nothing is seen and nothing can be isolated.

The daemon attaches the program to each VM's tap as the VM appears and takes it off when the VM goes. `shukractl programs` shows `tap  attached  N taps` once at least one is on.

## What it records

Directions are named from the guest's side. Frames the guest sends are `from_guest` (TCX ingress on the tap), and frames sent to it are `to_guest`.

- **Counters** per tap: packets and bytes each way, and packets and bytes dropped by isolation. `shukractl trace tap`, `GET /api/v1/trace/tap`, and `shukra_tap_*` on `/metrics`.
- **`guest_connect` events**: one per TCP SYN the guest sends (IPv4 and IPv6), with the guest's own source address, the destination and port, and the tap. A connect isolation dropped has `blocked: true`. At most 200 per tap per second, so a guest that floods SYNs cannot flood the event ring. The counters still see every packet.

The detection rules apply to these events exactly as they do to host connects: a `destinations` or `ports` rule that fires on a `guest_connect` produces a detection that is itself `guest_attributed: true` with `attribution: "guest-tap"`. A host connect and a guest connect to the same address are separate alerts, so one never hides the other.

## What guest_attributed means now

`guest_attributed` is `true` only when the event was seen on a VM's tap **and** the tap belongs to a VM in the current scan. A tap no VM owns produces an unattributed event, never a guessed name. Host `tcp_v4_connect` events are still `attribution: "qemu-process"` and `guest_attributed: false`: that is QEMU's own socket, not the guest.

Still not measured: CPU steal, and what runs inside the guest. A guest connect tells you which VM and which address, not which process.

## Isolate

`shukractl isolate <vm>` sets a flag on the VM's tap. While it is set, the program drops every frame on that tap except:

- ARP, and IPv6 neighbour discovery (ICMPv6 types 133 to 137), so the guest can still find an allowed address
- traffic to or from the **management allow list**

The allow list is required. Start the daemon with the networks an isolated VM must keep reaching, usually your management and monitoring networks and the default gateway they sit behind:

```bash
shukrad -isolate-allow 10.0.0.0/24,fd00:10::/64 ...
# or in /etc/shukra/env:  SHUKRA_EXTRA_ARGS=-isolate-allow 10.0.0.0/24
```

**Without an allow list, isolate is refused** (`applied: false`, result `refused`), because an isolated VM that could reach nothing could not be reached by the host that isolated it. A request is also refused for an unknown VM, a VM with no tap, or a daemon without the tap program.

`applied` is `true` only after the kernel program took the change on every tap of the VM. If some taps changed and some did not, the result is `partial`, `applied` is `false`, and what took effect is kept: a half-isolated VM is safer left contained than silently reopened.

`shukractl release <vm>` lifts it. The console's Isolate page enables the controls only when the daemon reports enforcement is available, and asks for a second confirmation that names what will be cut off and what stays reachable.

### It survives a restart, but not a gap

The daemon re-applies recorded isolations after a restart, when a VM comes back with a new tap, and when a tap appears after the request. A release is recorded too, so a released VM is not re-isolated.

The enforcement itself lives in the running daemon. **If `shukrad` stops or crashes, its TCX links close and the tap is open until the daemon starts again and re-applies.** Plan upgrades and restarts with that in mind; pinning the links so they outlive the process is not built yet.

### What isolation does not cover

- DHCP: a guest that must renew a lease will fail unless the DHCP server is on the allow list.
- VLAN-tagged frames and IPv6 extension headers are judged by their outer addresses only, and the SYN event needs the TCP header to follow the IPv6 header directly. Traffic that cannot be parsed is dropped while isolated.
- Non-TCP flows are counted and can be dropped but do not produce events.
- Isolation blocks the VM's tap. It does not stop the guest talking to another guest on the same host bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces.

## How it was checked

`scripts/test-tap.sh` builds a real network path with no KVM: a network namespace stands in for the guest, a veth pair's host end stands in for the tap, and a fake QEMU process names that interface. It checks refusal without an allow list; guest events and detections attributed to the VM; the tap counters; that an allowed address stays reachable and a non-allowed one is dropped, over IPv4, IPv6 and ping, with the same address reachable again after release; the blocked-connect event; re-application after a daemon restart; no re-isolation of a released VM; and detaching when the VM goes. It runs on Linux 6.6 or newer as root and is part of CI.
