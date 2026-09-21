# Guest traffic and isolation (the tap program)

Every other program in Shukra sees the VMM process: QEMU, or a FluxVM backend. This one sees the guest. It attaches TCX to the host side of each VM's tap, or to the host veth that stands in for that tap, so a frame it counts really is the guest's, and events from it are the only ones Shukra marks `guest_attributed: true`.

It does five things: it **counts** the guest's traffic, **records** what the guest connects to and what connects to it, **follows** each TCP handshake to see what became of it, can **isolate** the VM, and can hold it to an **egress policy**. A sixth question, *who dropped the packet*, is answered by its sibling program and has its own guide: [where packets die](drops.md). To use the two together to find lost traffic, see the [walkthrough](tutorials/08-lost-traffic.md).

| If you want to... | Read |
|---|---|
| Know what a tap needs, and how to tell it is working | [What it needs](#what-it-needs) and [How do I know it works](#how-do-i-know-it-works) |
| Trace a FluxVM, Cloud Hypervisor or Firecracker guest | [FluxVM](#fluxvm) |
| See what the guest connects to, looks up and negotiates | [What it records](#what-it-records), [DNS names](#dns-names), [TLS server names](#tls-server-names) |
| Cut a VM off, and know it stays cut off | [Isolate](#isolate) |
| Allow a VM only some networks, and try that out first | [Egress policy](egress-policy.md) |
| Learn what is normal for a VM and be told what is new | [Learned baselines](baselines.md) |
| Find out who dropped a VM's packets | [Where packets die](drops.md) |
| Find out why something is missing or wrong | [Troubleshooting](#troubleshooting) and [Limits](#limits) |

## What it needs

- Linux 6.6 or newer, for TCX. On an older kernel the program cannot attach: the daemon logs `tap program on <interface>: TCX needs Linux 6.6 or newer` (once per interface), `shukractl programs` shows `tap` as `detached`, and `shukractl doctor` reports the kernel (`kernel`, info). Host probes still run. There is no second datapath for older kernels.
- A VM with a tap interface. The daemon finds a VM's taps two ways and merges them: `ifname=tap0` on the QEMU command line, and the `iff:` line in `/proc/<pid>/fdinfo/<fd>` of each `/dev/net/tun` fd the process holds. The second is how libvirt VMs are found, since libvirt hands QEMU its `vnet0` as a file descriptor (`-netdev tap,fd=37`). Reading another user's fds needs the daemon to have `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which the shipped unit grants. If it cannot read them, that VM has no known tap and nothing is attached or isolated for it: a name is never guessed. A VM on user-mode networking has no tap either.

The daemon attaches the program to each VM's tap as the VM appears and takes it off when the VM goes. A netlink link notification does that immediately; the two-second scan is the backstop. The saved egress policy is written before the tap is reported as covered. It shares the hook politely: it returns `TCX_NEXT`, never `TCX_PASS`, so any other program attached to the same tap (Cilium, FluxVM's `fluxvm_egress`, or another tool) still runs after it. `TCX_PASS` would have accepted the packet and skipped them. `shukractl programs` shows `tap  attached  2 taps via tcx, enforcement survives a daemon restart` once at least one is on, and `detached` with the reason until then (for example `no VM tap interfaces to attach to yet`, which is normal on a host with no VM that has a tap, or `TCX needs Linux 6.6 or newer` on an older kernel). If there is no bpf filesystem the detail says `not pinned: enforcement lasts only while the daemon runs`. Guest traffic has no other hook. An older kernel is not a supported guest datapath.

## FluxVM

[FluxVM](https://github.com/zyvorai/fluxvm) boots a guest with QEMU, Cloud Hypervisor, Firecracker, or its own `fluxvm-hypervisor`. Shukra does not call FluxVM's API and does not load FluxVM's programs. On each scan, after it has walked `/proc` for `qemu-system*`, it reads FluxVM's VM store and joins each live record to the process and to the host interface that actually carries the guest's frames. The BPF programs are unchanged. KVM, scheduler and block counters follow the VMM's threads. Guest connects, UDP flows, DNS names, TLS server names, handshake outcomes, kernel drops and isolation follow that host interface.

### Where the record is

`state_dir` in `/etc/fluxvm.toml`, or `/var/lib/fluxvm` when that line is absent or the file is missing. The store is `{state_dir}/vms.json`: a JSON object whose keys are VM ids and whose values are records. A missing file, an empty file, or a file that does not parse is not an error. The QEMU scan stands, and the daemon keeps serving.

The fields read are `id`, `name`, `pid`, `tap_name` and `netns`. A record with no `pid`, or whose pid is not a live directory in the proc scan, is skipped. That is a stopped or deleted VM, not a guest Shukra failed to see.

`runtime` becomes `fluxvm`. The name and UUID come from the record, not from the VMM command line. FluxVM's QEMU argv does not pass `-name` or `-uuid`, so without the record those guests would show up as `qemu-unnamed` with whatever `ifname=` the inner tap happened to be.

### Which process

A pid the QEMU scan already found is updated in place. It is not listed twice. `cloud-hypervisor`, `firecracker` and `fluxvm-hypervisor` are added when that binary is `argv[0]`. Firecracker's `jailer` execs into `firecracker`, so the pid in the record is the Firecracker process, not a leftover jailer. Threads come from `/proc/<pid>/task`. A vCPU thread in that thread group owns the KVM counters the same way a QEMU `CPU n/KVM` thread does.

The process comm stays the binary. The kernel keeps 15 characters of it, so `cloud-hypervisor` is reported as `cloud-hypervis` and `fluxvm-hypervisor` as `fluxvm-hypervis`. `firecracker` and `jailer` fit.

A QEMU, libvirt or kubevirt process that is not in the store is left as the command line described it. `runtime=libvirt` and `runtime=kubevirt` are still labels from that command line, not guest agents.

### Which interface

Guest frames are not the VMM's sockets. They leave the guest on a tap. The daemon runs in the host network namespace and can only attach to an interface that exists there. It picks one, in this order, and does not keep the others:

1. **The edge FluxVM recorded**, when the file `/run/fluxvm/ebpf/vms/<id>/iface` exists and is not empty. `<id>` is the UUID with the hyphens removed. This is the interface FluxVM's own dataplane attached to, including a bridge-less direct tap whose guest device is not in the host namespace.
2. **The host veth of a per-VM netns**, when the record has `netns` set and that file does not. The name is `vh` plus the first 8 hex digits of the same id. FluxVM's default (`"netns": true`) builds this:

```text
host namespace                         VM netns eph-<8hex>
vh<8hex>  <---- veth pair ---->  vn<8hex> -- br<8hex> -- tap<8hex> -- guest
     ^
     TCX ingress = frames the guest sent
     TCX egress  = frames sent to the guest
```

The inner tap is `tap<8hex>`. It is not in the host namespace, so it is not the name Shukra stores and not the interface it attaches to. Directions match a normal tap: ingress is from the guest, egress is toward it. NAT on this path is POSTROUTING on the host, after the TCX hook, so a `guest_connect` still carries the guest's own address (a `169.254` address on the default netns), not the masqueraded one.

3. **`tap_name`**, when there is no netns. That is a host-bridge tap, usually `eph<8hex>`, or a macvtap, already visible in the host namespace.

`shukractl vms` prints that name under `taps=`. For a default netns guest it is `vh…`, not `tap…`. Compare it with `shukractl trace tap`. A name that is not in this namespace is still the doctor finding `vm-tap-other-netns`: Shukra does not enter the namespace. The unit does not have `CAP_SYS_ADMIN`, and the fix is not "set `"netns": false`". A FluxVM guest is supposed to be traced on the host veth. The warning remains for a tap the scan could not map, and for any other runtime whose tap really is elsewhere.

User-mode NAT (`network.mode` `user`, QEMU SLIRP) has no host interface. The VM is listed, `taps` is empty, there are no guest events, no drop counts and no isolation. `shukractl doctor` names it. Host-side KVM, scheduler and block counters still work, because those follow the process, not the tap.

### What each program attributes

| What | Joined by | Notes |
|---|---|---|
| KVM exits, on-CPU time, run-queue delay, block latency | The VMM's thread group | Block latency is the VMM's I/O, not a filesystem inside the guest. A `vhost-*` kernel thread outside the thread group is not included. |
| `vmm_file_open` and `vmm_syscall` | The VMM the calling process is (`vmm_watched`, the same pids as above), or descends from at any depth (recorded at fork), or, for a process that was already running before its VMM was seen, through up to three parents | `attribution` is `qemu-process`: what the VMM or something it started did. See [VMM tripwires](vmm-tripwires.md) |
| `exec` and `exit` | The parent's tgid, if that tgid is watched | The watched set is every VMM pid from the scan. `qemu-system*`, `cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor` and `jailer` are allowed execs, so a boot is not an unexpected-exec detection. `cpu`, `io`, `vhost` and `kvm` in the comm are allowed too. |
| Host TCP (`tcp_v4_connect`, `tcp_v6_connect`, retransmits) | The socket owner | `attribution` stays `qemu-process` for every backend. That string means "the VMM's socket, not the guest". It was not renamed, so a client that matches it still matches. |
| Guest connects, flows, inbound SYNs, DNS and TLS names, handshakes, drops, isolation | The host interface above | `attribution` is `guest-tap`. DNS and TLS names are read from the packets on that interface the same way they are on a QEMU tap. |

The live guest test, `scripts/test-live-guest.sh`, still boots two QEMU guests with `"netns": false` on a shared bridge. Those two have to reach each other on one L2 segment, which the default netns does not provide. It does not exercise the host-veth path. That path is covered by the identity tests in `internal/identity`.

## What it records

Directions are named from the guest's side. Frames the guest sends are `from_guest` (TCX ingress on the tap), and frames sent to it are `to_guest`.

- **Counters** per tap: packets and bytes each way, and packets and bytes dropped by Shukra itself (isolation, or an [egress policy](egress-policy.md) that is enforcing). Frames the host itself sent and the kernel looped back in (multicast) are not counted as the guest's. `shukractl trace tap`, `GET /api/v1/trace/tap`, and on `/metrics` `shukra_tap_bytes_total` and `shukra_tap_packets_total` (`direction` is `from_guest` or `to_guest`), `shukra_tap_dropped_packets_total` and the gauge `shukra_tap_isolated`.
- **`guest_connect` events**: one per TCP SYN the guest sends (IPv4 and IPv6), with the guest's own source address, the destination and port, the tap, and `proto: "tcp"`. A connect that isolation or an enforcing egress policy dropped has `blocked: true`, and one an [egress policy](egress-policy.md) judged to be outside its list carries `policy: "audit"` (it passed) or `policy: "enforce"` (it was dropped).
- **`guest_flow` events**: one per *new* UDP flow (`proto: "udp"`), so a guest's DNS, NTP or a UDP channel out is visible. A flow is announced when its first datagram is seen and again only after 60 seconds, so 20 datagrams on one flow are one event, and a new source port is a new flow. The flow table is a fixed-size LRU, so a guest cannot grow it, only turn it over. Multicast and broadcast (mDNS, SSDP, DHCP discovery) are counted in the tap's packets but produce no event. `policy` is set on a flow the same way as on a connect.
- **`guest_inbound` events**: one per TCP connection made **to** the guest, the other way round from `guest_connect`. `src` is the peer that connected, `dst` is the guest, `dport` is the guest port it reached, and `blocked: true` means isolation dropped the SYN. A retransmit of the same SYN is not announced again. This is how you see a service inside a VM being probed, or a watched network reaching in.
- **Handshake outcomes**, per tap and per direction (`shukractl trace tap`, `/api/v1/trace/tap`, and on `/metrics` `shukra_tap_connect_attempts_total`, `shukra_tap_connect_outcomes_total{direction,result}` and `shukra_tap_connect_retransmits_total`). The tap follows each SYN until it is answered: a SYN-ACK is **accepted**, an RST is **refused**, and a SYN nobody answers is **never answered** (`ignored`, for a connection made to the guest). Isolation's drops, and an enforcing egress policy's, are **blocked**. A repeat of the same SYN is a **retransmit**, not a new attempt. So every attempt is exactly one of accepted, refused, never answered or blocked, or is still waiting, and the counts add up. The time from SYN to SYN-ACK of the guest's own connections is a log2 histogram (`handshakeP50Ns`, `handshakeP99Ns`, `shukra_tap_handshake_seconds`), so a percentile can read up to twice too high. On `/metrics` the results are `accepted`, `refused`, `timed_out` and `blocked` outbound, and `accepted`, `refused`, `ignored` and `blocked` inbound.
- **`guest_dns` events**: the name a guest asked for in a DNS query over UDP port 53. See [DNS names](#dns-names).
- **`guest_tls` events**: the server name (SNI) in a TLS ClientHello the guest sent, with the protocols it offered and a fingerprint. See [TLS server names](#tls-server-names).
- Connect, flow and inbound events together are capped at 200 per tap per second, DNS names have a separate budget of the same size, and TLS hellos have their own (100 per tap per second), so a guest that floods SYNs, invents flows, resolves names or opens connections in a loop cannot flood a ring or starve another kind of event. The counters still see every packet, which is how you tell a capped tap from a quiet one: `shukra_tap_connect_attempts_total` keeps rising while the events do not.

The fields each kind carries, as they appear in `GET /api/v1/events` and `shukractl watch --json` (a field that does not apply is left out; a detection raised from one of these copies its fields):

| Kind | Fields beyond `kind`, `ts`, `vm`, `attribution` (`guest-tap`), `guest_attributed` |
|---|---|
| `guest_connect` | `proto: "tcp"`, `src` (the guest), `dst`, `dport`, `iface`, `blocked`, `policy` |
| `guest_flow` | `proto: "udp"`, `src` (the guest), `dst`, `dport`, `iface`, `blocked`, `policy` |
| `guest_inbound` | `proto: "tcp"`, `src` (the peer), `dst` (the guest), `dport` (the guest's port), `iface`, `blocked` |
| `guest_dns` | `proto: "udp"`, `dport: 53`, `src`, `dst` (the resolver), `iface`, `dns_name`, `qtype`, `dns_truncated`, `blocked` |
| `guest_tls` | `proto: "tcp"`, `src`, `dst`, `dport`, `iface`, `sni`, `alpn`, `tls_version`, `ja3`, `ech`, `tls_truncated`, `blocked` |

The source port is not in an event. `iface` is the interface Shukra attached to, which for a FluxVM guest on the default netns is the host veth, not the tap name inside the guest's namespace.

The detection rules apply to these events as they do to host connects. A `destinations` rule fires on any protocol. A `ports` rule fires on TCP unless it says `proto: udp` or `proto: any`, and on the guest's own connects unless it says `dir: in` (a connection made to the guest, matched on the port it reached) or `dir: any`, so a rule written before either was visible means what it always did. A `destinations` rule also fires when a watched network connects **in**, naming the peer. A detection on guest traffic is itself `guest_attributed: true` with `attribution: "guest-tap"` and carries the `proto`. A host connect and a guest connect to the same address, and TCP and UDP to the same address, are separate alerts, so none of them hides another.

Two features use these events without a rule of yours. [Learned baselines](baselines.md) learn the networks a guest connects to (from `guest_connect` and `guest_flow`), the sites it looks up (from `guest_dns` and `guest_tls`) and who connects in (from `guest_inbound`), and report what is new. An [egress policy](egress-policy.md) marks the connects and flows it judged, and raises its own detections. Both are off until you turn them on.

## DNS names

For a plain DNS query the guest sends to UDP port 53 (IPv4 or IPv6), the tap program checks that it is a query (`QR=0`, `OPCODE=0`, one question) and copies the first 128 bytes of the question section. The daemon decodes the name and the type and emits a `guest_dns` event: `dns_name` (lower-cased, dot-joined), `qtype` (`A`, `AAAA`, `NS`, `CNAME`, `SOA`, `PTR`, `MX`, `TXT`, `SRV`, `NAPTR`, `DS`, `DNSKEY`, `TLSA`, `SVCB`, `HTTPS`, `ANY`, or `TYPE<n>` for any other), the guest as `src` and the resolver as `dst`, with `blocked: true` if isolation dropped the query. The flow to port 53 still produces its own `guest_flow` event: the name adds to the flow and does not replace it.

- **Announced once a minute.** A name and type on a tap is announced when first seen and again after 60 seconds, so a guest that asks for the same name a hundred times is one event. `www.Example.com` and `www.example.com` are the same name. AAAA and A are different queries.
- **Its own budget.** At most 200 names per tap per second, separately from the connect events, so a resolver storm cannot starve them.
- **A name that does not fit** (the copy is 128 bytes of the question, so a name of more than about 120 characters, once the type and class are counted) is an event with `dns_truncated: true` and no `qtype`, and the labels that were read. A compression pointer, a response, a second question or something that is not DNS at all produces no event.
- **Sanitised.** Every byte that is not a printable character becomes `?`, and a name is cut at 253 bytes, so a hostile guest cannot put a line break or an escape sequence into a log, a terminal or a consumer.
- **A `dns` rule** (see [detection rules](tutorials/06-watchlist.md)) fires on a name by suffix, exact match or substring. It judges the name only: the resolver's address is not somewhere the guest connected.
- **Privacy.** A name identifies what a VM is doing. It is held in the event list, in the flight recorder (which `-data-dir` snapshots to `recorder.json` once a minute and on a clean stop), in the detection log (`detections.jsonl`) when a detection is raised about it, and in an [incident bundle](tutorials/09-after-the-fact.md#4-one-file-for-the-ticket) that covers the moment. `shukrad -dns-events=false` makes the program not look at DNS at all: no name is ever copied out of the kernel. The switch lives in a pinned map and the daemon sets it on every start, so it never depends on what a previous run left.

What it does not see: answers (so a name is not tied to the addresses it resolved to), queries over TCP, DNS over TLS or HTTPS, a second question in one packet, and a guest that talks to a resolver on a port other than 53. A packet that is not a query is ignored. Names are decoded in the daemon, not in the kernel, which is why a decoder bug cannot upset the verifier.

## TLS server names

DNS is not the only place a name is asked for: almost every connection a guest makes over TLS says which site it wants in the clear, in the **server name** (SNI) of its ClientHello, before anything is encrypted. It is also how a guest that uses DNS over HTTPS, or an address it was told by something other than DNS, is still seen going somewhere.

For a TCP segment the guest sends whose payload starts a TLS handshake (a handshake record, version 3.x, whose first message is a ClientHello), the tap program copies up to 1504 bytes of the payload, which is the whole first segment on an Ethernet MTU. The daemon decodes it and emits a `guest_tls` event:

| Field | What it is |
|---|---|
| `sni` | The server name, lower-cased and printable. Empty when the hello has none (it was made for an address, or the client hides it), and never a half name |
| `alpn` | The protocols offered, comma-separated (`h2,http/1.1`), at most 8 |
| `tls_version` | The highest version the client offered (`1.3`, `1.2`, ...) |
| `ja3` | The [JA3](https://github.com/salesforce/ja3) fingerprint: an MD5 of the version, ciphers, extensions, groups and point formats offered, in the order sent, GREASE left out. Present only when the whole hello was seen |
| `ech` | `true` when the hello carries Encrypted Client Hello. `sni` is then the outer, public name at most, and says nothing about the real site |
| `tls_truncated` | `true` when the hello did not end inside the copy |
| `src`, `dst`, `dport`, `iface`, `blocked` | The guest, the server, its port, the tap, and whether isolation dropped the segment |

The connection still produces its own `guest_connect` event: the name adds to it and does not replace it.

- **One event per connection.** A hello is announced when first seen; a retransmission of the same connection's hello within 30 seconds is not a second event. Unlike DNS, the same name is *not* collapsed: every connection is its own event, so a guest opening a hundred connections to a site is a hundred events, capped at 100 a second per tap on their own budget.
- **Sanitised.** Every byte that is not a printable character becomes `?`, a name is cut at 253 bytes, and a list is bounded, so a hostile guest cannot put a line break or an escape sequence into a log, a terminal or a consumer.
- **Cut short, and said so.** A hello longer than the copy, or split over segments (a modern browser or OpenSSL 3.5 or later, whose post-quantum key share makes a hello about 1.5 KB), is read as far as it goes. The name is usually in the first bytes and is still reported; `tls_truncated` is set and there is no JA3, because a fingerprint of part of a hello would be a different fingerprint.
- **Not fooled by random data.** The kernel program only takes a segment for a hello when it starts with a handshake record of version 3.0 to 3.4 whose first message is type 1 and shorter than 64 KiB, and the decoder checks again and refuses a hello that says it is longer than a TLS record. Encrypted data that happens to start the same way is not an event.
- **A `tls` rule** (see [detection rules](tutorials/06-watchlist.md)) fires on a name by suffix, exact match or substring, exactly like a `dns` rule, and the two do not judge each other's names. Learned [baselines](baselines.md) count a server name as the site it names, so a site a VM looked up by DNS is not new when it connects to it.
- **Privacy.** A name identifies what a VM is doing, and a fingerprint identifies its software. Both are held in the event list, the flight recorder (and so `recorder.json` and an incident bundle, as for [DNS names](#dns-names)) and, when a detection is raised about them, the detection log. The bytes copied from the kernel are decoded and thrown away: nothing but the fields above is kept, and the hello has no application data in it. `shukrad -tls-events=false` makes the program **not read a TCP payload at all**. The switch lives in a pinned map and the daemon sets it on every start.

### What it costs

Measured with [`scripts/bench-tap.sh`](../scripts/bench-tap.sh) on the production hypervisor (Intel Xeon E-2336, Linux 6.8), as nanoseconds per packet for the guest-to-host program, on a private copy with its own maps, each figure the median of five runs of two million:

| Packet | Before TLS names | TLS names off | TLS names on |
|---|---|---|---|
| Full data segment (1448 bytes) | 65 to 68 | 71 to 80 | 77 to 81 |
| Application-data record | 67 to 68 | 68 to 73 | 74 to 86 |
| Pure ACK | 68 to 73 | 67 to 73 | 68 to 83 |
| UDP datagram | 123 to 124 | 118 to 134 | 120 to 132 |
| A hello of a flow already announced | 67 to 69 | 71 to 78 | 131 to 154 |

Read it as a floor, since the same packet is run over and over and the caches are as warm as they will get. What it says is that the payload check adds about **10 to 15 ns to a data segment** (one array lookup and one 7-byte read), nothing to ACKs or UDP, and about 60 to 85 ns to the one segment per connection that is a hello. At a million data segments a second that is about 1 to 1.5% of one core. A hello that is announced also does a map update and a ring write, bounded at 100 a second per tap.

What it does not see: a name hidden by Encrypted Client Hello (only the outer one), QUIC and HTTP/3 (UDP), and a hello that does not begin at the start of a segment. TLS that starts after another protocol's exchange (STARTTLS in mail, for example) is seen, because the start of every data segment the guest sends is checked. It does not read the server's answer, so it does not know whether the connection succeeded, which certificate it got, or what was said. **JA3 says what kind of client library made the hello, not who the client is**: a client that randomises the order of its extensions, as current browsers do, has a different JA3 each time, and many programs share one. Treat it as a hint to compare, not as an identity.

## What guest_attributed means now

`guest_attributed` is `true` only when the event was seen on a VM's tap **and** the tap belongs to a VM in the current scan. A tap no VM owns produces an unattributed event, never a guessed name. Host `tcp_v4_connect` events are still `attribution: "qemu-process"` and `guest_attributed: false`: that is QEMU's own socket, not the guest.

Still not measured: the guest's own CPU steal counter (the host's view is vCPU preemption, see [signals](signals.md#vcpu-preemption)), and what runs inside the guest. A guest connect tells you which VM and which address, not which process.

## Isolate

Isolation drops everything but the management network. To drop only what a VM starts outside a list of networks it is allowed, and to try that list out first without dropping anything, see [egress policy](egress-policy.md), which uses the same allow list as its floor and the same pinned maps to outlive the daemon. When a tap is isolated and also has a policy, isolation wins and the policy is not consulted; releasing the VM leaves the policy as it was. A [response](responses.md) can isolate a VM when a detection fires, but only by asking for the same thing `shukractl isolate` does, so everything on this page applies to it.

`shukractl isolate <vm>` sets a flag on the VM's tap. While it is set, the program drops every frame on that tap except:

- ARP, and IPv6 neighbour discovery (ICMPv6 types 133 to 137), so the guest can still find an allowed address
- traffic to or from the **management allow list**

The allow list is required. Start the daemon with the networks an isolated VM must keep reaching, usually your management and monitoring networks and the default gateway they sit behind:

```bash
shukrad -isolate-allow 10.0.0.0/24,fd00:10::/64 ...
# or in /etc/shukra/env:  SHUKRA_EXTRA_ARGS=-isolate-allow 10.0.0.0/24
```

A bare address is a /32 or /128. The list is read when the daemon starts, so changing it means a restart, and it holds at most 256 networks for IPv4 and 256 for IPv6 (the size of the kernel's tries). `shukractl security <vm>` prints it, and `shukractl doctor --json` shows it under `isolate`.

**Without an allow list, isolate is refused** (`applied: false`, `audit.result` `refused`), because an isolated VM that could reach nothing could not be reached by the host that isolated it. A request is also refused for an unknown VM, a VM with no tap, or a daemon without the tap program.

`applied` is `true` only after the kernel program took the change on every tap of the VM. If some taps changed and some did not, the result is `partial`, `applied` is `false`, and what took effect is kept: a half-isolated VM is safer left contained than silently reopened.

`shukractl release <vm>` lifts it. The console's Isolate page enables the controls only when the daemon reports enforcement is available, and asks for a second confirmation that names what will be cut off and what stays reachable.

### Isolation outlives the daemon

The tap program's links and maps are pinned under `/sys/fs/bpf/shukra/tap/`, so the kernel keeps enforcing when `shukrad` is not running:

- **A crash or `kill -9`** leaves every tap exactly as it was. An isolated VM stays isolated, and its allowed management addresses keep working, because the program and its maps are still there.
- **A restart** adopts what is pinned: it points the existing links at the freshly loaded program (`BPF_LINK_UPDATE`, so there is no gap and no second pair of links), and reads the isolation flag back from the kernel, so what it reports is what the kernel is enforcing. Counters continue across the restart.
- **A graceful stop** (`systemctl stop`) detaches every tap that is **not** isolated and has no **enforcing** egress policy, so nothing of Shukra is left on a VM's interface once it is off. An isolated tap, or one whose policy is enforcing, is left enforcing, on purpose: stopping the daemon must not reopen a VM that was cut off. A tap that is only auditing has nothing to keep and is detached, and the daemon puts it back under its policy on the next start.
- **A VM that went away while the daemon was down** has its stale link removed on the next start, and an interface that was replaced under the same name is re-attached fresh.

The recorded isolations still matter. When the kernel state is gone but the record says "isolated", as after a reboot, the daemon re-applies it on start. A release is recorded too, so a released VM is not re-isolated.

To lift enforcement without the daemon, for an emergency or an uninstall:

```bash
shukrad -detach-all -data-dir /var/lib/shukra
```

It removes every pinned link and map, so every VM is open again (an enforcing egress policy included, since it lives in the same maps), and with `-data-dir` it also records a release for each isolated VM, so the next start does not isolate them again. Without `-data-dir` it says that a restart will re-apply them. The `.deb` runs this on removal, since removing the package removes the thing that could release an isolation.

`-detach-all` records releases for isolations only. It does not touch `policies.json`, so a daemon started afterwards puts every recorded egress policy back on its VM. To end a policy for good, run `shukractl policy remove <vm>` while the daemon is up, or stop the daemon and move `policies.json` aside before starting it again (see [egress policy](egress-policy.md#files)).

Pinning needs a bpf filesystem at `/sys/fs/bpf` (present on any systemd host). Without one the daemon runs unpinned, logs that, and reports `durable: false` (on `GET /api/v1/security`, as `not pinned` in `shukractl programs`, and as an `isolate` warning in `shukractl doctor`); then isolation lasts only while the daemon runs and the `reason` of an isolate response says so. A new map is a new pin, so a build that only adds maps (as the handshake counters did) keeps every existing map and link and isolation is untouched. If a build changes an existing map's layout, the old pins cannot be reused: the daemon replaces them, logs it, and re-applies the recorded isolations, so the cost is a brief gap on upgrade.

### What isolation does not cover

- A SYN is judged "never answered" after 3 seconds, counted when the counters are read (on every scan and every API or `/metrics` read), because BPF has no timers. A server that answers after that is counted as never answered and not as accepted. The table of pending SYNs has a fixed size (65,536), so under a SYN flood the oldest are forgotten uncounted; `attempts` still counts every one, so `attempts` can then exceed the sum of the outcomes by what was forgotten. A daemon restart forgets handshakes that were in flight. Within 3 seconds of a burst of connections `attempts` also exceeds the sum, by the ones still waiting: that is not an error.
- DHCP: a guest that must renew a lease will fail unless the DHCP server is on the allow list.
- The tap reads no VLAN tag: a VLAN-tagged frame is not IPv4, IPv6 or ARP to it, so it is **dropped while the VM is isolated** and is not judged by an egress policy. An IPv6 packet with extension headers is judged by its addresses, but the SYN event needs the TCP header to follow the IPv6 header directly. An IPv4 or IPv6 frame too short to hold its own header has no address to judge and is passed on while isolated, unjudged and uncounted as blocked.
- ICMP and other protocols are counted and can be dropped, but do not produce events. A UDP event carries addresses and ports; the name in a DNS query is a separate `guest_dns` event, and the server name of a TLS connection a separate `guest_tls` event.
- Isolation blocks the VM's tap. It does not stop the guest talking to another guest on the same host bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces.
- A VM whose tap is not in the host namespace, and that the scan could not map to one, has nothing to attach to. It is listed with that tap name but has no tap counters, no guest events and cannot be isolated. `shukractl doctor` names it (`vm-tap-other-netns`, a warning). Compare `taps` on `GET /api/v1/vms` with `GET /api/v1/trace/tap`. A tap that exists here but is not traced yet is a separate, informational finding (`vm-tap-untraced`): normal for the moment after a VM starts, and a problem if it stays. FluxVM's default netns is mapped before this check; see [FluxVM](#fluxvm).

### What the counters count

`to_guest` is what the host offered to the tap, counted before the tap's own driver runs. If the guest is not reading its NIC (a VM stopped at its firmware, or a guest whose NIC driver never came up), the tun driver drops those frames and the kernel's `tx_packets` stays put while `to_guest` keeps rising. Its `tx_dropped` climbs instead. `from_guest` is what the guest sent.

## When guests cannot reach each other

Shukra's program only drops a frame on a tap that is **isolated**, or whose [egress policy](egress-policy.md) is **enforcing**, and it counts every frame it drops (`dropped` in `trace tap`). So if a VM's traffic is being lost and `dropped` is 0, something else is dropping it, and the `drops` program says what: [where packets die](drops.md). The connection counters above say whether the connection got an answer at all. Together they separate a refusing destination, a dropping host and a guest that is not reading its NIC, and the [walkthrough](tutorials/08-lost-traffic.md) shows how.

Three things a real host showed, all about FluxVM and none about a bug in the tap program, are in [where packets die](drops.md#what-a-real-host-showed): two guests with the same MAC, a dataplane policy that allows only some CIDRs and ports, and (before host-veth tracing) a guest tap left inside a netns the daemon could not see. The third is now traced; the first two are still FluxVM configuration.

## How do I know it works

Four commands, in the order that finds the problem soonest:

```bash
shukractl programs               # tap  attached  2 taps via tcx, enforcement survives a daemon restart
shukractl vms                    # each VM you expect shows taps=<interface>, not taps=-
shukractl trace tap --vm web     # from_guest and to_guest packets rise while the guest is in use
shukractl watch                  # a connection from the guest appears within a moment
```

`watch` prints one line per event. From inside the guest, `curl http://198.51.100.7/` should produce, on the host:

```text
2026-09-20T03:00:01Z  guest_connect  guest-tap  vm=web  dst=198.51.100.7
```

`guest-tap` is the point: it is the guest's own SYN, seen on its tap. If the same connection appears only as `tcp_connect  qemu-process`, that is QEMU's socket, and the tap is not attached for this VM.

Then check that the numbers add up, since a tap that is attached but wrong is worse than none:

- **Packets against the kernel's.** `from_guest` packets are the guest's transmissions and `to_guest` are the host's transmissions to it, which is what `ip -s link show <tap>` calls RX and TX. The [live guest test](testing.md#the-live-guest-test) checks they are equal on real KVM guests; on a busy tap they differ by what moves between two reads, and `to_guest` runs ahead of TX when the guest is not reading its NIC ([What the counters count](#what-the-counters-count)).
- **Connections against themselves.** For each direction, once a few seconds of quiet have passed, `attempts = accepted + refused + never answered + blocked`. The line in `shukractl trace tap` is laid out that way so the sum can be checked by eye:

```text
  vm=web  tap=vnet3  from_guest=<bytes> B/<packets> pkts  to_guest=<bytes> B/<packets> pkts  dropped=0 pkts  isolated=false
      connects out: 17 attempts = 5 accepted + 6 refused + 4 never answered + 2 blocked  (1 retransmits, handshake p50 <ns>ns p99 <ns>ns)
      connects in:  7 attempts = 3 accepted + 2 refused + 2 ignored + <n> blocked  (<n> retransmits)
```

The attempt and outcome counts in that sketch are the ones the tap rig asserts on GitHub's kernel (see [How it was checked](#how-it-was-checked)); the rest is left for your own host to fill in.

- **Isolation, on a VM you can afford to lose.** `shukractl isolate <vm>` must print `applied  true` and the taps it changed, `shukractl trace tap --vm <vm>` must then show `isolated=true` and `dropped` rising, and `shukractl release <vm>` must undo it. `applied  false` with `enforcement  not_attached` means nothing changed on the datapath, and the reason line says why.

## Troubleshooting

What it looks like when the tap program is not doing what you expect, and what to look at first.

| What you see | What it means | What to do |
|---|---|---|
| `tap  detached`, the log says `TCX needs Linux 6.6 or newer` (doctor `kernel`, info) | The kernel has no TCX. Guest traffic is not supported on that kernel | Upgrade to 6.6 or newer. The programs that follow the VMM (`kvm`, `sched`, `block`, `net`, `vmm`) are unaffected |
| `tap  detached  no VM tap interfaces to attach to yet` (doctor `program-tap`, info) | No VM in the scan has a tap Shukra can name | Nothing, until a VM with a tap starts. If VMs are running, see the next rows |
| A VM shows `taps=-` (doctor `blind-vms`) | User-mode networking has no host interface. Or a libvirt VM whose tap fds the daemon could not read | Give the daemon `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` (the shipped unit does). A name is never guessed |
| Doctor `vm-tap-other-netns` (warn) | The tap is named but is not in the network namespace the daemon runs in, and it is not a FluxVM netns the scan could map to its host veth | Put the tap in the host namespace. Shukra does not enter another namespace |
| Doctor `vm-tap-untraced` (info) that stays | The interface exists but the attach failed | `shukractl programs` and the daemon's log: it is logged once per interface and reason, so search the journal for `tap program on` |
| Events have `iface` but no `vm`, or `guest_attributed: false` | The tap belongs to no VM in the current scan, so nothing is guessed | Wait one scan (2 seconds). If it stays, compare `taps` on `GET /api/v1/vms` with `GET /api/v1/trace/tap` |
| `trace tap` counts rise but there are few or no `guest_connect` events | The 200 events per tap per second cap, or the guest is sending no SYNs (it is using established connections) | `shukra_tap_connect_attempts_total` counts every SYN whatever the cap |
| No `guest_dns` events | `-dns-events=false`; the guest's resolver is not on UDP port 53 (DNS over TCP, TLS or HTTPS is not read); the same name and type within the last 60 seconds; or the 200-a-second cap | Check the daemon's arguments (`SHUKRA_EXTRA_ARGS` in `/etc/shukra/env`). A `guest_flow` event to port 53 shows the guest is asking |
| No `guest_tls` events | `-tls-events=false`; QUIC or HTTP/3 (UDP); a hello that does not start at the beginning of a segment; or the 100-a-second cap | The connection still shows as `guest_connect` |
| `guest_tls` with an empty `sni` | A hello for an address, or one that hides the name; if `ech` is true the name is only the outer one | Nothing: that is what the hello said |
| `attempts` is larger than the outcomes added up | The last 3 seconds of connections are still waiting, or a SYN flood pushed the oldest out of the 65,536-entry pending table | Read again after a few seconds of quiet |
| `to_guest` rises but the interface's TX does not | The guest is not reading its NIC, so the tun driver drops what the host offers | `shukractl trace drops` shows `FULL_RING`; see [where packets die](drops.md) |
| `dropped` is 0 but traffic is being lost | Something other than Shukra is dropping it | [Where packets die](drops.md), and `bpftool net show dev <tap>` for another program on the tap |
| `isolate` prints `applied false` | No `-isolate-allow`, an unknown VM, a VM with no tap, or the tap program is not loaded. `partial` means some taps took it and some did not, and what took effect is kept | The `reason` line names which. Doctor `isolate` says the same |
| An isolated VM has lost DHCP, DNS or its gateway | Everything but ARP, neighbour discovery and the allow list is dropped | Put those servers and the gateway on `-isolate-allow`, and restart the daemon |
| Isolation or a policy is gone after a reboot | The kernel state is not kept across a reboot. The recorded isolations are re-applied on start; a policy is put back from `policies.json` | `shukractl doctor` says if there is no `-data-dir` (`persistence`) or no bpf filesystem to pin on (`isolate`) |

## Limits

Every fixed size in the tap program, so that a number in an alert can be read against what could have been recorded. All are set in `bpf/tap.bpf.c`.

| What | Limit | When it is hit |
|---|---|---|
| Taps with the program | 1,024 (the size of the per-tap maps) | A tap past it cannot be counted or isolated |
| Connect, flow and inbound events | 200 per tap per second, in all | Events stop until the next second. Counters do not |
| DNS name events | 200 per tap per second, on their own | Same |
| TLS hello events | 100 per tap per second, on their own | Same |
| UDP flow announced again | after 60 seconds; the table holds 65,536 flows (an LRU) | The oldest flow is forgotten, so it can be announced twice |
| DNS name announced again | after 60 seconds; 16,384 names (an LRU) | The oldest is forgotten |
| DNS question copied | 128 bytes; a name is cut at 253 characters | `dns_truncated` |
| TLS hello copied | 1,504 bytes; a hello is announced again after 30 seconds; 16,384 hellos (an LRU) | `tls_truncated`, no `ja3` |
| ALPN protocols reported | 8 | The rest are left out |
| SYNs waiting for an answer | 65,536 (an LRU); a SYN is never answered after 3 seconds | The oldest is forgotten uncounted |
| Management allow list | 256 networks for IPv4 and 256 for IPv6 | The daemon reports the list could not be loaded, and isolate is unavailable |
| Egress policy | 1,024 networks per VM; 16,384 per address family across all VMs | See [egress policy](egress-policy.md#limits) |
| Event rings | 256 KiB for connects and flows, 256 KiB for DNS, 1 MiB for TLS | A full ring drops the newest event in the kernel, and nothing counts that. A sample the daemon cannot decode is counted as lost, never guessed at |

## How it was checked

The full account is in [testing](testing.md). For the tap program:

- **`scripts/test-tap.sh`** builds a real network path with no KVM (a namespace for the guest, a veth for the tap, a fake QEMU naming it) and runs on a real kernel in CI. It checks refusal without an allow list; guest events and detections attributed to the VM; the counters; that an allowed address stays reachable and a non-allowed one is dropped over IPv4, IPv6 and ping; that isolation survives a `kill -9`, a restart and a graceful stop and is lifted by `-detach-all`; a real `tun` tap; UDP flows and their rules; drops from a real `tc` filter, told apart from Shukra's own; **DNS names** (case folding, repeats announced once, A and AAAA, IPv6, a name too long for the copy, malformed and non-query packets ignored, a `dns` rule, a blocked query, and `-dns-events=false` and back across restarts); **TLS server names** (real `openssl` hellos with the name, protocols, version and fingerprint, the same client having the same JA3, IPv6, a hello with no name, plain HTTP and malformed records ignored, a long name kept whole, a hello longer than the copy reported as cut short with no fingerprint, a `tls` rule, and `-tls-events=false` and back across restarts); and **every TCP handshake outcome both ways with exact counts**: on GitHub's kernel, 17 outbound attempts came out as 5 accepted, 6 refused, 4 never answered and 2 blocked with 1 retransmit, and 7 inbound as 3 accepted, 2 refused and 2 ignored, and the identity attempts = accepted + refused + never answered + blocked held.
- **`scripts/test-live-guest.sh`** boots two real KVM guests through FluxVM, with `"netns": false` on a shared bridge so they can reach each other, and checks the same things end to end: the taps are found and attached as hot-plugs, events are attributed with the guest's own address, packet counts equal the kernel's `rx_packets` and `tx_packets`, the guests reach each other, an accepted and a refused connection are seen from both taps, the guest's DNS lookup arrives with exactly the name it asked for and a repeat is one event per cycle, and deleting the VMs detaches everything. The default per-VM netns is not what this script boots; that mapping is covered by the identity tests. See [FluxVM](#fluxvm).

- **Egress policy** has its own section of the rig (15) and `scripts/test-tap-progrun.sh`, which runs hand-built packets through a private copy of the program; see [egress policy](egress-policy.md#how-it-was-checked). **VMM tripwires** are section 16, see [VMM tripwires](vmm-tripwires.md#checked).

The rig must never run on a hypervisor already running Shukra: it shares the pin directory and its cleanup detaches every tap.
