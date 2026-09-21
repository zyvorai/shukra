# Security

Shukra observes by default, and can isolate a VM only when you give it a management allow list. It runs as root on your hypervisor, next to the VMs it watches, so this page says who and what it trusts, what it can see, what it can do, and what a hostile guest, a compromised VMM or someone who can reach its API can do to it.

If you have found a vulnerability, go to [reporting a vulnerability](#reporting-a-vulnerability).

## Threat model

Shukra is a privileged daemon on a hypervisor. It loads eBPF programs, reads `/proc`, serves an HTTP API and keeps records of what your VMs did. The parties that touch it are not equally trusted:

| Party | Trusted? | What it can do, and what limits it |
|---|---|---|
| **The host: its kernel, its root user, its `/proc`** | Yes, entirely | Shukra reads `/proc` and believes it. A user who is root on the host can stop, replace or read Shukra, and Shukra is **not a defence against a compromised hypervisor**. That is out of scope |
| **The operator with the admin key** | Yes | Everything the API can do: isolate or release any VM, apply, confirm or remove an egress policy, approve or reject a proposed response, forget a learned baseline. There is one admin key and no per-person identity: the actor recorded for an action is a label the caller supplies (`X-Shukra-Actor`), not a proof |
| **A holder of the read-only key** | For reading | Reads everything the API serves, including `/metrics`, the event stream, the flight recorder and incident bundles, which name your VMs, addresses, DNS and TLS names and file paths. Cannot change anything: every request that is not `GET` or `HEAD` is refused |
| **An API caller with no key** | No | Gets `/healthz`, `/readyz` and the console's static files, and nothing else |
| **A guest** | No | Chooses every byte it sends. Can make Shukra do work and record events, within the limits [below](#every-table-is-bounded). Cannot change what Shukra attributes to it, cannot read or write anything of Shukra's through the tap, and cannot get another VM isolated or judged |
| **A VMM** (a QEMU process and what it starts) | Watched, not trusted | It is the process a guest escape lands in, so it is the thing the [tripwires](docs/vmm-tripwires.md) watch. Shukra reads its command line and file descriptors to learn a VM's tap, and a taken-over VMM can rewrite its own command line. A VMM that is root on the host is host root, above |
| **The destinations of your alert sinks** | Not with your data | A webhook, syslog or file receives every detection, which names VMs and addresses. Signed with `SHUKRA_WEBHOOK_SECRET` if you set one |

**In scope.** What a guest can do to Shukra or through Shukra's own enforcement; what the API lets a caller do with each credential; what Shukra writes to disk and sends out; the tap program and the other eBPF programs (each must pass the kernel's verifier and never index memory unchecked); the deployed unit's privileges.

**Out of scope.** A compromised hypervisor kernel or host root. What a guest does that never crosses its tap or a traced kernel path. Anything inside a guest: Shukra has no agent and cannot see a process, a file or a login in it. Tampering with `/proc`. Denial of service by someone who already holds the admin key.

## What it reads, and what it never does

- **It never runs anything inside a guest.** There is no agent. Everything is read from the host: `/proc`, kernel tracepoints, and the host side of each VM's tap interface. Where FluxVM is installed, three more files are read: `/etc/fluxvm.toml` (read whole, but only its `state_dir` line is used: nothing else is kept, logged or served, including any token in it), the VM store `{state_dir}/vms.json`, and `/run/fluxvm/ebpf/vms/<id>/iface`. Shukra does not call FluxVM's API and does not load its programs.
- **It does not read application payloads.** The eBPF programs count and sample metadata. The tap program reads Ethernet, IP, TCP and UDP headers to count packets, follow TCP handshakes and name a flow's addresses and ports. The drops program reads which device dropped a packet and why. The `kvm`, `sched`, `block` and `net` programs count exits, scheduling, block requests and the host's own connects. HTTP, TLS and other application data are not parsed or copied, with the exceptions below.
- **What it can attribute is bounded.** Host TCP events are connects from a process, joined to a QEMU thread group when the PID matches: they are QEMU's own traffic, not the guest's. Traffic seen on a VM's tap is the guest's, and only that is marked `guest_attributed`. Shukra never names a guess: an unowned tap or PID stays `unattributed`.

### The exceptions to "no payloads"

Three things take content, or something close to it, from a guest or a VMM. Each is bounded, decoded in the daemon, and has a switch.

| What | How much is copied, and what is kept | Turn it off |
|---|---|---|
| **DNS names.** The first question of a plain DNS query the guest sends to UDP port 53 | The kernel copies at most 128 bytes (the name and the type) and the daemon records a `guest_dns` event: the name, lower-cased, cut at 253 bytes, and the type. Answers, other UDP and everything else are not read | `shukrad -dns-events=false`: the program does not look at DNS at all |
| **TLS ClientHello.** The first segment a guest sends to start a TLS handshake | The kernel copies up to 1,504 bytes of a segment that begins with a handshake record, before anything is encrypted. The daemon decodes the server name (lower-cased, cut at 253), the protocols offered, the version and a JA3 fingerprint, records a `guest_tls` event and **discards the bytes**. A hello holds no application data, and nothing after it is read: not the answer, not the certificate, not the rest of the connection | `shukrad -tls-events=false`: the program does not read a TCP payload at all |
| **VMM file paths.** The files a QEMU process, or a program it started, opens | The `vmm` program copies the path as the process gave it (up to 256 bytes) with the program's name, its pid and whether it asked to write. Never the contents, and only for VMM processes, which in steady state open none | `shukrad -vmm-tripwires=false`: the program is not loaded |

A name says what a VM is doing, a fingerprint says what software it runs and a path can name a person or a secret, so all three are **sensitive data** (see [data that identifies people](#data-that-identifies-people)). The `sched` program also records the command name of a host task that took a vCPU's CPU, so `kubectl`, `cilium-agent` or one of your own services can appear in the API and on `/metrics`.

## Every table is bounded

A guest controls what it sends and a busy host controls how many processes it runs, so nothing that they can fill is allowed to grow. When a table is full the oldest entry is forgotten (an LRU) or the newest event is not reported, and the counters still count. The limits, from the programs and the daemon:

| What | Bound | At the bound |
|---|---|---|
| **Tap program: what a guest can fill** | | |
| Pending TCP handshakes (`pending_syn`) | 65,536 entries | The oldest is forgotten uncounted. `attempts` still counts every SYN |
| UDP flows (`udp_flows`) | 65,536 | The oldest is forgotten and would be announced again. A flow is announced once and again after 60 s |
| DNS names seen (`dns_seen`) | 16,384 | A repeat of one name and type on a tap is announced once a minute |
| TLS flows (`tls_flows`) | 16,384 | A retransmitted hello within 30 s is not a second event |
| UDP peers whose answers are not judged (`egress_udp_in`) | 65,536 | The oldest is forgotten, and its answer is judged as a new flow |
| Events per tap per second | 200 connect events, 200 DNS, 100 TLS, each on its own budget | The excess is not reported and does not reach the ring. The counters still see every packet |
| Event rings | 256 KiB (connects), 256 KiB (DNS), 1 MiB (TLS) | A record that does not fit is lost |
| **`vmm` program** | | |
| Reported calls per VMM per second | 300, for the VMM and everything it started | Counted, and reported once as a `vmm-flood` detection when the second ends |
| Descendants of a VMM (`vmm_desc`) | 8,192 | The least recently used is forgotten, and is then found again through its parents (up to three) while they live |
| VMM processes watched (`vmm_watched`) | 4,096 | Set from a scan of `/proc`, so a guest does not fill it |
| Event ring | 256 KiB | A record that does not fit is lost |
| **Enforcement** | | |
| Management allow list | 256 IPv4 and 256 IPv6 networks | A longer list fails to load, and isolate is refused with that reason |
| Egress policy | 1,024 networks per VM, 16,384 across all VMs | A longer list for a VM is refused; a change the kernel map cannot hold is put back |
| Confirmation timer | 30 seconds to 24 hours | A request outside that is refused |
| **Daemon** | | |
| Event list | 2,048 events, shared between six classes with guaranteed shares (512 guest, 512 host network, 256 each for notable, process, latency and other) | The oldest of the class furthest over its share is dropped, so one noisy class cannot push out another's evidence |
| Flight recorder | 4,096 events per VM, a ring | The oldest is overwritten |
| Detection suppression table | 4,096 keys | Full of live keys, a detection is let through unrecorded: it fails toward alerting |
| Learned baselines | By default 2,048 items per kind per VM, remembered 30 days, at most 20 new-item alerts per VM per day | The item unseen longest is dropped. Past the daily cap new items are learned and not reported |
| Responses in memory | 500 actions, 50 incident bundles; 200 bundles on disk | The oldest is dropped |
| Detection, isolation and snapshot logs | Roll at 16 MiB to one `.1` file | Disk use stays near twice that per log |
| `vmm` rules file | 256 `paths` and 256 `ignore` entries | The file is refused (on a reload the previous rules stay) |

The per-thread programs (`kvm`, `sched`, `block`, `net`) keep fixed-size LRU maps keyed by thread id, of 8,192 to 65,536 entries. A host process, not a guest, can turn those over. The per-tap maps are keyed by interface index and hold at most 1,024 taps.

## A hostile guest

A guest controls the bytes it sends. Shukra is built so that cannot hurt it:

- Every table it can fill is bounded (above), and every event a guest can cause is rate-limited, so a guest that floods SYNs, invents flows or asks for a million names cannot grow memory or flood the ring or the daemon.
- Under isolation, a frame that is not IPv4, IPv6 or ARP is dropped, a VLAN-tagged frame included, and an IP frame is judged by its outer addresses. A frame cut too short to hold its own Ethernet or IP header has no address to judge and is passed on without a verdict. Nothing from a packet is used to index memory unchecked, and each program passes the kernel verifier.
- A guest cannot change what Shukra attributes to it: attribution comes from the tap's owner, found on the host, not from anything in the packet. So a guest cannot make another VM's traffic look like its own, and cannot get another VM isolated, dropped by a policy or blamed for a detection. It can only make **itself** the subject of detections, and, if you enabled a response in `enforce` mode for a rule it can trigger, get itself isolated.
- **Text from a guest is made safe before it goes anywhere.** A DNS name or a TLS server name is lower-cased, cut at 253 bytes, and every byte that is not a printable character becomes `?`, so a name cannot carry a line break or an escape sequence into a log, a terminal or a consumer. The ALPN list is at most eight names, each cut at 32 characters and made printable in the same way, and the whole list is cut at 64. A decoder refuses a record it cannot trust and counts it as lost, never guessed at. A hello that says it is longer than a TLS record, or a name that runs past the copy, is reported as cut short and has no fingerprint.
- **What a guest can do is generate load.** A very high packet rate costs CPU in the tap program on that tap (about 70 to 150 ns a packet on the reference host: [what it costs](docs/tap.md#what-it-costs)), and a flood of unanswered SYNs makes the pending table forget the oldest entries. Neither hides the flood: the packet and byte counters count every frame, and `attempts` counts every SYN.
- **A guest that can reach the daemon's API address can try its key.** The shipped unit listens on `127.0.0.1:30970`, so a guest cannot reach it unless you bind a wider address. Plain HTTP on a non-loopback address is refused unless you pass `-allow-insecure-http`. Prefer TLS in front of loopback (see [the API](#the-api)).

## A compromised VMM

The VMM is where a guest escape lands, and it is the most exposed process on the host, so Shukra watches it and does not pretend to confine it. The `vmm` program reports every file a QEMU process (or anything it started, at any depth) opens and every `ptrace`, `process_vm_readv`/`writev`, `mount`, `unshare`, `setns`, module load and `kexec` it makes; a path on the sensitive list, or one of those calls, is a critical or high detection that names the VM. The list includes `/etc/shadow`, `/root/.ssh`, `/proc/*/mem`, the docker and containerd sockets, and **`/etc/shukra` and `/var/lib/shukra`**, which hold Shukra's key and data. See [VMM tripwires](docs/vmm-tripwires.md) for the list and the limits.

**A tripwire is not a sandbox.** It reports; it does not stop anything, and it can be walked round:

- The path is read when the call starts. One that changes after that is not seen, and a symlink is not followed, so `/tmp/x` that points at `/etc/shadow` is `/tmp/x`.
- A relative path is resolved from `/proc` while the process is still there; from a short-lived process that has gone, it stays as it was given and cannot be judged.
- A VMM that does none of these is not seen at all: it does not have to open a file or make one of these calls to be compromised.
- Descendants are tracked in a fixed table of 8,192, and past 300 reported calls a second the rest are counted and not listed, so what is inside a flood is not visible. That a flood happened is itself a critical detection.
- A process that was already running before Shukra first saw its VMM is found through its parents, up to three.

A VMM that is root on the host can also stop or replace `shukrad`. Stopping the daemon does not lift isolation or an enforcing egress policy, which live in pinned kernel maps, but host root can unpin those too.

## Isolation and egress policy

`shukractl isolate` and `POST /api/v1/isolate` drop a VM's tap traffic through a TCX program, except ARP, IPv6 neighbour discovery and the networks in `-isolate-allow`. Without that list, or without the tap program, isolate is **refused**, because an isolated VM that could reach nothing could not be reached by the host that isolated it.

- **`applied` is true only after the kernel took the change** on every tap of the VM. A half-applied isolation is kept contained and reported `partial`, not silently reopened.
- **It fails closed.** The tap program's links and maps are pinned in the bpf filesystem, so a crash, `kill -9` or restart leaves an isolated VM isolated. A graceful stop leaves an isolated tap, and a tap enforcing an egress policy, enforcing on purpose. `shukrad -detach-all` is the deliberate way to lift enforcement without the daemon. This needs a bpf filesystem at `/sys/fs/bpf`; without one the daemon says so and isolation lasts only while it runs, and `shukractl doctor` warns.
- **It returns `TCX_NEXT`, never `TCX_PASS`,** so other programs on the tap, such as Cilium, still run.
- **The management allow list is a floor.** `-isolate-allow` is read when the daemon starts and is never dropped, by isolation or by any egress policy.

What isolation does **not** do:

- ARP and IPv6 neighbour discovery always pass, to any address. Isolation stops a guest's IP traffic; it does not stop it sending ARP or neighbour-discovery frames to whatever shares its link.
- It drops what crosses the VM's tap. It does not touch vhost-user or SR-IOV interfaces, a VM whose tap is not in the host's network namespace, or anything that is not network traffic (vsock, virtio-serial, shared folders). The guest keeps running. See [what isolation does not cover](docs/tap.md#what-isolation-does-not-cover).
- A guest that must renew a DHCP lease fails unless its DHCP server is on the allow list.

An **egress policy** is the other enforcement. It can drop what a VM *starts* (a TCP SYN, or a UDP datagram that is not multicast and not an answer) outside a list of networks. It is off until an admin applies one; it audits (drops nothing) before it enforces; enforcing needs the management allow list as a floor, a record that survives a restart, and a timer that reverts it unless a person confirms; and the routes that change one need the admin key. **It is not a firewall.** It judges networks, not ports or names. It does not judge ICMP, ARP, established connections, multicast or broadcast, or a UDP reply. A guest that sends segments that are not a SYN cannot open a connection with them, but is not stopped from sending them. A new tap has no policy for up to two seconds after a VM comes back with one. See [egress policy](docs/egress-policy.md).

## The API

- The API expects `Authorization: Bearer` matching `SHUKRA_API_KEY`. Only `/healthz`, `/readyz` and the console's static files (`/` and `/assets/`) are served without one. **The dev default (`shukra`) exists only when that variable is unset**, and the daemon says so at start. `-no-auth` is the only way to serve without a key.
- `SHUKRA_READONLY_KEY` adds a key that can read (including `/metrics` and the event stream) but not isolate, release, apply a policy or decide a proposal: it is refused every method but `GET` and `HEAD`. Give that one to Prometheus and dashboards. It must differ from the admin key, or the daemon refuses to start.
- Keys are compared in constant time (both are always compared, so the time does not say which matched), never appear in any response, in `doctor`, or in `systemctl show` (the install puts the key in `/etc/shukra/env`, mode `0600`, not in the unit). The console holds the key in memory for one page load and asks again after a reload.
- The API is plain HTTP on loopback unless you pass `-tls-cert` and `-tls-key`. The shipped unit binds `127.0.0.1:30970`. A non-loopback listen without TLS is refused unless `-allow-insecure-http` is set, and the daemon then says the key crosses the network in the clear. `-no-auth` on a non-loopback address is refused even then. `SIGHUP` reloads a renewed certificate and keeps the old one if the new one does not load.
- Alert webhooks are HMAC-signed when `SHUKRA_WEBHOOK_SECRET` is set, and the daemon warns when it is not. See [alert sinks](docs/tutorials/07-alert-sinks.md).
- Details are in the [API reference](docs/api.md).

### The dev key and plain HTTP: check your own install

**The API key is the admin key. With the dev key, anyone who can reach the port can read everything Shukra knows and isolate any VM on the host.** Two things make that easy to end up with, and both are worth checking on a host you deployed a while ago:

- **The shipped unit listens on `127.0.0.1:30970`.** It does not accept connections from other machines. To open it, terminate TLS in a proxy on the hypervisor, or pass `-listen` with `-tls-cert` and `-tls-key`. `-listen 0.0.0.0:30970` without TLS does not start unless you also pass `-allow-insecure-http`, which sends the bearer key in the clear.
- **A fresh install generates a random key and never uses `shukra`. An install over an older deploy keeps the key it finds**, and an older deploy kept the key, dev key included, in the unit file: the installer carries it into `/etc/shukra/env` rather than lock you out. `deploy-remote.sh` likewise keeps the key already on the host unless you export `SHUKRA_API_KEY`. So a host first deployed long ago can still be running `shukra`.

Run `shukractl doctor` on every host. It reports the dev key on a non-loopback address as a **failure**, `-no-auth` as a failure, a key shorter than 16 characters as a warning, plain HTTP on a non-loopback address as a warning (a failure if the key is the dev key), and no read-only key as information. Fix it by generating a key (`openssl rand -hex 16`), setting `SHUKRA_API_KEY=` to it in `/etc/shukra/env` and restarting. That root-only file (mode `0600`) also holds the read-only key and the webhook secret.

## Privilege

The deployed service runs as root with six capabilities, `NoNewPrivileges`, a read-only filesystem apart from its data directory, and a restricted set of address families (`AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_NETLINK`):

| Capability | Why it is needed |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, raise the map limit |
| `CAP_NET_ADMIN` | load and attach the TCX tap program. Without it the program fails with `operation not permitted` |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun file descriptors of a QEMU that runs as another user. libvirt passes taps as fds, so the names are not on the command line |

The last two are broad. They are used only to read `/proc/<pid>/fd` and `fdinfo`, and the daemon never calls `ptrace`. If you run no libvirt VMs you can drop them; those VMs then have no known tap. Each was verified necessary by removing it under systemd. No program needs `CAP_SYSLOG`: the drops program asks the kernel to name a function itself. On a kernel older than 5.8, which has no `CAP_BPF`, the install removes the two capability lines and the service runs with full root capabilities and the rest of the hardening.

The unit also sets `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `SystemCallArchitectures=native` and `UMask=0077`. The eBPF programs it loads run in the kernel, so each must pass the kernel's verifier, and each is tested against a real kernel ([testing](docs/testing.md)).

## Data that identifies people

The daemon's data directory (`-data-dir`, `/var/lib/shukra` when deployed) is `0700` and its files `0600`, because detections and isolation records name your VMs and addresses. That includes `snapshots.jsonl` (the coarse history that past verdicts stand on), `baselines.json`, `policies.json`, `actions.jsonl` and the `incidents/` bundles. `shukractl incident --out` writes its file with mode `0600` too.

- Events, detections and the flight recorder hold VM names, UUIDs, the addresses a guest talked to and, unless you turn it off, the DNS and TLS names it used and the paths a VMM opened. With `-data-dir` they are written to disk. **Treat that directory as sensitive, and the alert sinks as a place that data leaves the host.**
- `baselines.json` lists the networks and names each VM talks to (mode 0600), so it is as sensitive as the event list. Forgetting a VM's baseline is recorded as a detection naming who did it, since it is a way to hide a change.
- `policies.json` names VMs and the networks each may reach (mode 0600), and is as sensitive as `baselines.json`.
- The scheduler program's command names can show a service of yours in the API and on `/metrics`, as above.
- **Responses** are the one place Shukra can act on a VM without a person at the keyboard, so they are the most constrained thing in it: they only propose unless a rules file says `mode: enforce` and names the rules, they cannot act without a management allow list, protected VMs are never touched, a cap (three isolations an hour by default) and a cooldown bound them, every decision is recorded with its evidence (`actions.jsonl`, `incidents/`, mode 0600) and the approve and reject endpoints need the admin key. See [responses](docs/responses.md).

## Reporting a vulnerability

Report vulnerabilities to the Zyvor maintainers, privately. **Do not open a public issue or pull request that includes exploit detail.** Say what you found and where, the version (`shukrad -version`), the kernel and distribution, how to reproduce it, and what an attacker gains, in terms of the parties in the [threat model](#threat-model): a guest, a VMM, an API caller with no key or with the read-only key.

The reports most useful to us are the ones that cross a line in that table: a guest that changes what is attributed to it, or gets another VM isolated, blocked or blamed; a guest that grows a table or floods a ring past its bound; text from a guest that reaches a log, terminal or consumer unsanitised; a read-only or unauthenticated caller that changes state or reads what its key should not; an isolation or policy that is lifted without a person or its timer; a program that fails the verifier on a kernel it claims to support. What is out of scope is listed above.
