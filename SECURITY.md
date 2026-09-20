# Security

Shukra observes by default, and can isolate a VM only when you give it a management allow list. It runs as root on your hypervisor, so this page says what it can see, what it can do, what it trusts, and what a hostile guest can do to it.

## What it reads, and what it never does

- **It never runs anything inside a guest.** There is no agent. Everything is read from the host: `/proc`, kernel tracepoints, and the host side of each VM's tap interface. Where FluxVM is installed, three more files are read: `/etc/fluxvm.toml` (read whole, but only its `state_dir` line is used: nothing else is kept, logged or served, including any token in it), the VM store `{state_dir}/vms.json`, and `/run/fluxvm/ebpf/vms/<id>/iface`. Shukra does not call FluxVM's API and does not load its programs.
- **It does not read application payloads.** The eBPF programs count and sample metadata. The tap program reads Ethernet, IP, TCP and UDP headers to count packets, follow TCP handshakes and name a flow's addresses and ports. The drops program reads which device dropped a packet and why. HTTP, TLS and other application data are not parsed or copied.
- **The exceptions are DNS names and TLS server names.** For a plain DNS query the guest sends to UDP port 53, the tap program copies the first question (at most 128 bytes: the name and the type) and Shukra records it as a `guest_dns` event. For a TLS ClientHello, the first segment a guest sends to start a handshake (a handshake record, before anything is encrypted), the program copies up to 1504 bytes, the daemon decodes the server name, the protocols offered, the version and a fingerprint (JA3) from it, records them as a `guest_tls` event and discards the bytes. A hello holds no application data, and nothing after it is read. Answers, other UDP, the rest of a TLS connection and everything over HTTPS are not read. A name says what a VM is doing, and a fingerprint says what software it runs, so both are treated as sensitive data (below). `shukrad -dns-events=false` makes the program not look at DNS at all, and `-tls-events=false` makes it not read a TCP payload at all.
- **What it can attribute is bounded.** Host TCP events are connects from a process, joined to a QEMU thread group when the PID matches: they are QEMU's own traffic, not the guest's. Traffic seen on a VM's tap is the guest's, and only that is marked `guest_attributed`. Shukra never names a guess: an unowned tap or PID stays `unattributed`.

## Isolation

`shukractl isolate` and `POST /api/v1/isolate` drop a VM's tap traffic through a TCX program, except ARP, IPv6 neighbour discovery and the networks in `-isolate-allow`. Without that list, or without the tap program, isolate is **refused**, because an isolated VM that could reach nothing could not be reached by the host that isolated it.

- **`applied` is true only after the kernel took the change** on every tap of the VM. A half-applied isolation is kept contained and reported `partial`, not silently reopened.
- **It fails closed.** The tap program's links and maps are pinned in the bpf filesystem, so a crash, `kill -9` or restart leaves an isolated VM isolated. A graceful stop leaves an isolated tap enforcing on purpose. `shukrad -detach-all` is the deliberate way to lift enforcement without the daemon.
- **It returns `TCX_NEXT`, never `TCX_PASS`,** so other programs on the tap, such as Cilium, still run.
- Isolation blocks the VM's tap. It does not stop a guest talking to another guest on the same bridge unless that traffic crosses this tap, and it does not touch vhost-user or SR-IOV interfaces. See [guest traffic and isolation](docs/tap.md).

## The API

- The API expects `Authorization: Bearer` matching `SHUKRA_API_KEY`. **The dev default (`shukra`) exists only when that variable is unset**, and the daemon says so at start. On a non-loopback address `shukractl doctor` reports it as a failure. `-no-auth` is the only way to serve without a key.
- `SHUKRA_READONLY_KEY` adds a key that can read (including `/metrics` and the event stream) but not isolate or release. Give that one to Prometheus and dashboards.
- Keys are compared in constant time, never appear in any response, in `doctor`, or in `systemctl show` (the deploy puts the key in `/etc/shukra/env`, mode `0600`, not in the unit).
- The API is plain HTTP unless you pass `-tls-cert` and `-tls-key`, and the daemon warns when it serves plain HTTP on a non-loopback address. With plain HTTP the bearer key crosses the network in the clear: use TLS or bind to `127.0.0.1`. `SIGHUP` reloads a renewed certificate.
- Alert webhooks are HMAC-signed when `SHUKRA_WEBHOOK_SECRET` is set. See [alert sinks](docs/tutorials/07-alert-sinks.md).
- Details are in the [API reference](docs/api.md).

## Privilege

The deployed service runs as root with six capabilities and a read-only filesystem apart from its data directory:

| Capability | Why it is needed |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, raise the map limit |
| `CAP_NET_ADMIN` | load and attach the TCX tap program. Without it the program fails with `operation not permitted` |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun file descriptors of a QEMU that runs as another user. libvirt passes taps as fds, so the names are not on the command line |

The last two are broad. They are used only to read `/proc/<pid>/fd` and `fdinfo`, and the daemon never calls `ptrace`. If you run no libvirt VMs you can drop them; those VMs then have no known tap. Each was verified necessary by removing it under systemd. No program needs `CAP_SYSLOG`: the drops program asks the kernel to name a function itself.

The daemon's data directory is `0700` and its files `0600` (including `snapshots.jsonl`, the coarse history that past verdicts stand on, and any incident bundle `shukractl incident --out` writes), because detections and isolation records name your VMs and addresses.

## A hostile guest

A guest controls the bytes it sends. Shukra is built so that cannot hurt it:

- Every table keyed by packet contents (flows, pending TCP handshakes) is a **fixed-size LRU**: a guest can turn it over, not grow it.
- Events from a tap are **rate-limited** (200 per tap per second), so a guest that floods SYNs or invents flows cannot flood the event ring or the daemon. The counters still see every packet.
- Frames that cannot be parsed are counted and, under isolation, dropped. Nothing from a packet is used to index memory unchecked, and each program passes the kernel verifier.
- A guest cannot change what Shukra attributes to it: attribution comes from the tap's owner, found on the host, not from anything in the packet.
- A guest chooses the DNS names it asks for. A name is decoded in the daemon, lower-cased, cut at 253 bytes, and every byte that is not a printable character becomes `?`, so a name cannot carry a line break or an escape sequence into a log, a terminal or a consumer. Names are announced once a minute per tap and name (a fixed-size table), and at most 200 per tap per second, on their own budget so they cannot starve the connect events.
- What a guest **can** do is generate load: a very high packet rate costs CPU in the tap program on that tap, and a flood of unanswered SYNs makes the pending table forget the oldest entries uncounted (`attempts` still counts every one).

## Data that identifies people

Responses are the one place Shukra can act on a VM without a person at the keyboard, so they are the most constrained thing in it: they only propose unless a rule file says `mode: enforce` and names the rules, they cannot act without a management allow list, protected VMs are never touched, an hourly cap and a cooldown bound them, every decision is recorded with its evidence (`actions.jsonl`, `incidents/`, mode 0600) and the approve and reject endpoints need the admin key. See [responses](docs/responses.md). `baselines.json` lists the networks and names each VM talks to (mode 0600), so it is as sensitive as the event list; forgetting a VM's baseline is recorded as a detection naming who did it, since it is a way to hide a change. The scheduler program records the command name of a host task that took a vCPU's CPU, so `kubectl`, `cilium-agent` or the name of one of your own services can appear in the API and on `/metrics`. Events, detections and the flight recorder hold VM names, UUIDs, the addresses a guest talked to and, unless you turn it off, the DNS names it looked up. With `-data-dir` they are written to disk. Treat that directory as sensitive, and the alert sinks as a place that data leaves the host.

## Reporting

Report vulnerabilities to the Zyvor maintainers. Do not open a public issue that includes exploit detail.
