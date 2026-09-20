# Testing

Shukra's claims are about what a real kernel does, so most of its tests load real programs and drive real packets. This page says what each test proves, what it needs, and, the part that matters most, **which of them are safe to run on a hypervisor that is already running Shukra and which are not**.

The short version: unit tests run anywhere; the kernel tests need Linux and root; one script (the tap rig) must **never** run on a production host; and the live guest test is the one built for a production host.

## What is safe where

| Test | Run it on a hypervisor already running Shukra? |
|---|---|
| Go unit tests, console tests | Yes, and on a Mac. They load nothing |
| `make test-bpf` | Yes. It compiles the loaders and runs the decoders; the kernel tests inside it skip unless `SHUKRA_BPF_TEST=1` |
| `TestKernelIntegration*`, `TestKernelPreemption` | Yes. They load their own programs, nothing is pinned, and they touch no daemon. For the few seconds they run, a second copy of the hot-path programs runs beside the daemon's |
| `scripts/test-tap-progrun.sh` | Yes. A private copy of the tap program in its own mount namespace, attached to nothing |
| `scripts/bench-tap.sh` | Yes, for the same reason |
| `scripts/test-live-guest.sh` | Yes. It creates two disposable VMs, never touches another VM, never isolates anything, and deletes what it made (see [what it leaves behind](#the-live-guest-test)) |
| `scripts/test-install.sh` | Yes. It installs into a temporary root and touches no service |
| **`scripts/test-tap.sh` (the rig, `make test-tap`)** | **No. Never.** It shares the tap program's pin directory with the daemon and its cleanup removes every pinned link on the host. See [why](#never-run-it-on-a-live-hypervisor) |

## The layers

| Layer | Command | Needs | What it proves |
|---|---|---|---|
| Go unit tests | `make test` (`go test ./...`) | Go 1.27 | Logic: joins, windows, resets, rules, findings, the API, the CLI, and every decoder that reads a record by offset. Runs on any OS on the stub build |
| Console tests and build | `make web` (`npm ci`, `npm test`, `npm run build`) | Node 22 | The console's units, its type-check and its production build. See [the console tests](#the-console-tests) |
| Loader build | `make test-bpf` | Linux, clang, bpftool, kernel BTF, `make generate` first | The `shukrabpf` build compiles, and the tap record decoder's tests pass |
| Kernel integration | `make test-kernel` | Linux, root, `make generate` first | The real programs loaded into this kernel and checked against load the test makes itself. See [the kernel tests](#the-kernel-tests) |
| Tap program, packet by packet | `scripts/test-tap-progrun.sh` | Linux, root, bpftool, python3, `unshare`, `make generate` first | The kernel's own verdict for every rule of the egress policy. See [below](#the-tap-program-packet-by-packet) |
| Tap rig | `make test-tap` (`scripts/test-tap.sh`) | Linux 6.6+, root or passwordless sudo, `ip`, `curl`, `python3`, `tc`, `iptables`, `openssl`, `bpftool`, a machine **not** running Shukra | The tap program, isolation, drops, DNS and TLS names, egress policy, tripwires and responses, end to end, with no KVM. See [the rig](#the-tap-rig) |
| Live guest | `make test-live-guest` (`scripts/test-live-guest.sh`) | A hypervisor with [fluxvm](https://github.com/zyvorai/fluxvm), `/dev/kvm`, a running `shukrad`, `sudo` | Real KVM guests seen by a running daemon. See [the live guest test](#the-live-guest-test) |
| Cost of the tap program | `scripts/bench-tap.sh OBJECT...` | Linux, root, bpftool, python3, `unshare` | Not a test: nanoseconds per packet on this kernel |
| Installer | `scripts/test-install.sh` | bash | `deploy/install.sh`, staged into a temporary root: a first install generates a private random key and never the dev key, the unit is rendered and holds no key, a second install keeps the operator's rules, key and env lines, a supplied key replaces the old one, and an incomplete tree is refused. It does not build or open the tarball or the `.deb` |

## Unit tests and the untagged decoders

There are 538 Go test functions in 57 files, and 528 of them run on the default build. The other ten are compiled only with `-tags shukrabpf` on Linux: seven decoder tests for the tap record (`internal/observe/tap_bpf_test.go`) and the three kernel tests below. Every one of the 528 runs on a Mac, which is what keeps CI and a laptop honest about the logic.

What makes that possible is a rule in [development](development.md): **a record the kernel writes is decoded by offset in a file that has no build tag**, so its decoder is unit-tested on any OS. The tests build a record byte by byte, decode it, and check what comes out, and they check what must not come out:

- `internal/observe/decode.go` (the ring records of the older programs), `dns.go`, `tls.go` and `vmm.go` are untagged, with `decode_test.go`, `dns_test.go`, `tls_test.go` and `vmm_test.go` beside them. They pin that a record that is too short, the wrong size or of an unknown kind is refused and counted lost rather than guessed at, that a name or path from a guest is made printable (a control byte becomes `?`) and bounded, and that only the bytes the length field claims are ever read, never what was left in the buffer.
- The TLS decoder is tested against `internal/observe/testdata/tls_hellos.json`, ClientHellos captured from real clients (Python's `ssl`, OpenSSL and curl), whose JA3 is compared with the value a separate implementation, in Python, worked out from the same bytes, and against every prefix of a hello, none of which may panic.
- `internal/bpfgen` has untagged helpers with their own tests: how an allow-list network becomes a trie key (`egress_test.go`), and how the layout of the kernel's `kfree_skb` tracepoint is recognised or refused with the reason (`kfree_format_test.go`, `symbol_test.go`).

The tap record's decoder (`decodeTap`) is currently in a tagged file, so its tests run under `make test-bpf` and not on a Mac.

## The kernel tests

`make test-bpf` runs `go test -count=1 -tags shukrabpf ./...`. That builds the loaders (so a compile error in a tagged file fails here and not on a hypervisor) and runs the tap decoder tests. The three kernel tests in it skip unless `SHUKRA_BPF_TEST=1` and root.

`make test-kernel` builds `bin/observe.test` and runs it as root with `-test.run TestKernelIntegration`, which is what CI does too. The pattern is an unanchored regular expression, so it runs `TestKernelIntegration` and `TestKernelIntegrationVMMTripwires`, and **does not run `TestKernelPreemption`**, whose name does not contain it. Run that one by name.

- **`TestKernelIntegration`** (`internal/observe/integration_bpf_test.go`) requires the `sched`, `block` and `net` programs to attach (`kvm` is not required: its tracepoints depend on the kvm module and the CPU). Counters are keyed by thread id, so each subtest locks its goroutine to one OS thread and reads that thread's row, which nothing else on the machine can move, so the connect counts, the exec filter and the histogram identity are exact. It checks:
  - **connects**: five IPv4 refusals, three IPv6 and four through a dual-stack socket to a v4-mapped address are counted exactly once each (the dual-stack case goes through two kernel functions and must not count twice);
  - **block bytes**: 32 MiB written and read with `O_DIRECT` are counted as between 85% and 125% of that, not exactly, because the block layer sometimes dispatches a request from a kernel worker and that request is charged to the worker's row (about 3% of reads in one run on a 6.8 kernel); the operations and the slowest write are recorded; and every completed request is in the latency histogram exactly once (skipped where the filesystem refuses `O_DIRECT`);
  - **the exec filter**: three programs and one shell started by the watched process are reported with their parent, and the shell's own children are not;
  - **connect events** carry the destination for both address families.
- **`TestKernelIntegrationVMMTripwires`** (`vmm_integration_bpf_test.go`) loads the real `vmm` program, with the test process standing in for a QEMU process, and checks it against calls the test makes itself: an open by the watched process and its write flag; a program it starts and its children at any depth (eight shells down); a job whose parent has exited (a daemonising shell does not escape); a process that was already running before the VMM was seen; an unwatched process, which must report nothing; a relative path and one relative to a descriptor; a path longer than the buffer; each of `ptrace`, `mount`, `unshare`, `setns` and `process_vm_readv`/`writev` with its arguments; and the limit: more than 300 a second is counted and reported once as a flood. The C was mutation-checked: fifteen breakages (the fork hook, the descendant lookup, the walk through parents, the child or the VMM recorded wrongly, the caller itself, the limit, the flood report, an argument swapped, the pid taken from the thread) each made it fail.
- **`TestKernelPreemption`** pins a busy "taker" and a busy "victim" to one CPU. The victim must be charged roughly half the run and the taker must be named by the command the test gave it. A third thread on the same CPU that runs briefly and sleeps is the control: sleeping is not being preempted, so it must not be charged, and removing the runnable check from the program makes the test fail.

All three load their own unpinned copies, so they can run on a hypervisor that is running Shukra:

```bash
go test -c -tags shukrabpf -o /tmp/observe.test ./internal/observe
sudo SHUKRA_BPF_TEST=1 /tmp/observe.test -test.run 'TestKernelIntegration|TestKernelPreemption' -test.v
```

Build the test binary as yourself and run only that binary as root, as CI does, so root never needs your Go module cache. (`sudo env "PATH=$PATH" SHUKRA_BPF_TEST=1 go test ...` also works if root can reach the module cache.)

## The tap program, packet by packet

`scripts/test-tap-progrun.sh [OBJECT]` checks the tap program's egress policy on a real kernel with no namespace, veth or VM. It re-executes itself under `unshare -m`, mounts a fresh bpffs there, loads the tap object as a private copy (its own maps, attached to nothing) and runs hand-built packets through it with `BPF_PROG_TEST_RUN` (`bpftool prog run`), so what is asserted is the verdict the kernel program itself gives: `TCX_NEXT` (let it through) or `TCX_DROP`. Nothing a running `shukrad` has pinned is reachable from that namespace, so it is safe on a production host. `OBJECT` defaults to the CO-RE object `make generate` writes to `internal/bpfgen`, and takes any other, which is how a mutant is tried (below).

It makes 39 checks: nothing is judged while the policy is off; audit lets everything through and counts exactly the packets and bytes that enforce would have dropped; enforce drops a SYN or a UDP datagram outside the list and passes one inside; the management network passes although it is not on the list; established TCP data, a SYN-ACK, ICMP, multicast and broadcast are not judged; a UDP answer passes only after the datagram it answers, and only on the same ports and peer; IPv4 and IPv6, a `/0`, a `/32` and a `/128` (a host entry does not let its neighbour through); one tap's list is not another's; and isolation still wins and is not counted against the policy. Every rule was mutation-checked by breaking the C and confirming a check failed.

## The tap rig

`scripts/test-tap.sh` builds a real network path with no KVM. A network namespace stands in for the guest, a veth pair's host end stands in for the tap, and a fake QEMU process (a shell loop whose command line names that interface, which is how the daemon finds a VM's tap) stands in for the VM. It builds `shukrad` with `-tags shukrabpf` itself (or takes one from `SHUKRAD=`), starts it on `127.0.0.1:30990` with a throwaway data directory and rules file, and removes everything it made when it ends. It needs Linux 6.6+ for TCX, so a red run on an old kernel is a real answer.

Its sections are numbered by behaviour, not by the order they run in; they run in the order below, because a few depend on the state an earlier one leaves. Every check asserts an exact value, not "greater than zero".

| Section | What it proves |
|---|---|
| 1. Isolate is refused without a management allow list | The tap program attaches to the VM's tap found from its command line; `isolate` is not applied and says why; traffic is unaffected |
| 2. Guest traffic is seen and attributed | A `guest_connect` names the VM, the guest's own address and the destination, and is `guest_attributed`; a destination rule fires on it, attributed to the guest; the host-side detection for the same address is not called the guest's; host `tcp_connect` events are never marked `guest_attributed`; the tap counters count both directions |
| 3. Isolation drops what is not allowed and keeps what is | Through TCX, over IPv4, IPv6 and ping (so ARP and neighbour discovery still pass): the allowed address is reachable, the other is dropped; the blocked attempt is an event marked `blocked`; the tap reports `isolated` with dropped packets |
| 4. Isolation survives a daemon restart | The restarted daemon reports the VM still isolated, having adopted the pinned links |
| 5. Release lifts it | The address is reachable again, and a restart does not isolate a released VM |
| 9. Guest UDP | Twenty back-to-back datagrams on one flow are one event; a new source port is a new flow; multicast is counted in the tap's packets (exactly three more) and produces no event; IPv6; a destination rule and a `proto: udp` port rule fire and a port with no rule does not; under isolation UDP to the allowed address is delivered and to the others dropped, over both families, and the dropped flow is an event marked `blocked` |
| 10. Drops | A real `tc` filter on the tap drops twenty pings; the kernel's `TC_INGRESS` count on that tap rises by at least twenty, and they are counted as `otherDrops` and not as Shukra's; then Shukra's own isolation drops twenty and they are **not** blamed on another program. Doctor names the VM and the tap, `/metrics` carries the kernel's reason, and the function that dropped them is named |
| 11. TCP handshake outcomes | Both ways, with exact counts: 17 outbound attempts are 5 accepted, 6 refused, 4 never answered and 2 blocked, with 1 retransmit that is not a new attempt; 7 inbound are 3 accepted, 2 refused and 2 ignored; attempts equal the sum of outcomes; the handshake histogram holds every accepted connection; inbound connections are `guest_inbound` events and an inbound port rule fires on them |
| 12. Guest DNS names | Case folding and repeats announced once, A and AAAA, IPv6, a name too long for the copy, a compression pointer, a response, a non-DNS payload and a two-question packet each producing no event, a `dns` rule, a blocked query still an event, and `-dns-events=false` and back across restarts |
| 14. Guest TLS server names | Real `openssl` hellos (name, protocols, version, a 32-hex JA3, the same client having the same JA3), one event per connection, IPv6, a hello with no name, plain HTTP, a ServerHello and application data ignored, a 194-character name kept whole, a hello longer than the copy reported cut short with no fingerprint, a `tls` rule that the `dns` rule for the same suffix does not also judge, and `-tls-events=false` and back |
| 15. Egress policy | Audit passes everything and marks what is outside as events, low detections and counters; enforce drops only what the guest starts outside the list (IPv4, IPv6, UDP), counts it as blocked and in the tap's dropped counters, and never the management address; a server keeps working (a connection made to the guest from an unlisted address is answered, and so is a UDP datagram); enforcing is refused without the management allow list and without a timer or `permanent`; an unconfirmed policy goes back to the audit it replaced when its time runs out; a confirmed one survives `kill -9` (fail closed), a restart and a graceful stop; a lost record leaves an orphan that `remove` puts right; and isolation beats a policy and releasing it leaves the policy |
| 16. VMM tripwires | A fake VMM whose children open sensitive files and make each call: what the VMM's own children open is events and no detection; the detections and their severities; a path cleaned before it is judged (`/etc/../etc//sudoers`); a wildcard pattern; the rules file adding and exempting paths; a write; a relative path resolved from a live process; `unshare`, `ptrace`, `mount` and `setns`; a flood past the limit; a process that is not a VMM's is not seen; and `-vmm-tripwires=false` and back |
| 13. Responses | A proposing response leaves a pending proposal and changes nothing; approving without the admin key is refused (401) and nothing is decided; approving isolates the VM and records who approved which action; a decided proposal cannot be decided again; an enforcing response isolates at once with nobody deciding, and releases the VM itself when its time comes |
| 8. Enforcement outlives the daemon | After `kill -9` an isolated VM is still cut off and the management address still works; the restarted daemon adopts the two pinned links rather than attaching a second pair; a graceful stop of a tap that is not isolated detaches everything, and of an isolated one leaves it enforcing; with the kernel state lost (as after a reboot) the daemon re-applies the recorded isolation; `-detach-all` opens the VM with no daemon running and records the release, so a restart does not isolate it again |
| 7. A real `tun` tap | The host's own looped-back multicast is not counted as the guest's, and the three frames the guest really wrote (3 x 42 = 126 bytes) are |
| 6. The tap comes off when the VM goes | With the fake QEMU killed, the program reports `detached` |

Two sections wait for a real timer (the egress policy's confirmation and a response's release, a minute each), so the run is slow.

### Never run it on a live hypervisor

The rig's daemon and a production `shukrad` share the pin directory `/sys/fs/bpf/shukra/tap`, and the tap program's maps are pinned by name. So a rig daemon opens the production maps, and:

- it **rewrites the management allow list** (`SetTapAllow` clears the pinned `allow4` and `allow6` maps and writes the rig's own, `10.99.0.1/32` and `fd99::1/128`), so an isolated production VM loses the network that manages it;
- it sets the DNS and TLS switches (`dns_cfg`, `tls_cfg`) on every start, and the rig starts with `-dns-events=false` and `-tls-events=false` in turn;
- it scans `/proc`, finds the real QEMU processes and their taps, and would adopt the production daemon's pinned links on them; its graceful stop then detaches the ones that are not isolated;
- its cleanup, and section 8, run `shukrad -detach-all`, which removes **every** pinned link and map on the host, so isolation and enforcing egress policies stop surviving a restart of the real daemon.

Run it on a machine that is not running Shukra, or in CI. For a change to the tap program, that means the pull request's own CI run is the check, and the queue on GitHub can be slow.

## The live guest test

`scripts/test-live-guest.sh` is the same checks with a real KVM guest, and the one test built to run on a working hypervisor. It boots two disposable Ubuntu cloud images with fluxvm on a host bridge (`"netns": false`, so the two guests share layer 2 and can reach each other): the guest under test and a peer. Each has one vCPU, 768 MiB and a 5 GiB disk. cloud-init makes the guest, every 75 seconds, send a TCP SYN, twenty UDP datagrams on one flow and three multicast datagrams, connect to a listener on the peer, connect to a closed peer port, send hand-built DNS queries (the same name in two spellings, and an AAAA) to an address nothing answers, and send a hand-built TLS ClientHello to the peer. The script then checks a running daemon against what the kernel says. fluxvm's default per-VM netns, traced on the host veth, is not what this script boots; that mapping is the identity unit tests. See [FluxVM](tap.md#fluxvm).

What it checks, in its own sections:

- **0 and 1.** The tools, the image and the bridge are there, the daemon answers with this key, and the tap program is attached or waiting for its first VM. Then it creates both VMs.
- **2.** The daemon lists both VMs with a tap each, in the host's network namespace; the tap program attaches to both as hot-plugs (two more taps traced, four more TCX programs, one in each direction per tap); nothing is isolated or dropped.
- **3.** It applies an egress policy in **audit** mode to the guest under test (its peer and the bridge's gateway on the list), which drops nothing and needs no management allow list, and waits for the guest's own connect and UDP flow to arrive as events.
- **4.** Over one more 75-second cycle, the tap's from-guest and to-guest packet counts equal the kernel's `rx_packets` and `tx_packets` on the tap, within five.
- **5.** What the events say: a TCP connect is a `guest_connect` with protocol tcp and a UDP flow a `guest_flow`; every guest event is `guest_attributed` with attribution `guest-tap` and names this VM; the source is the guest's own address; twenty datagrams on one flow are one event per cycle; multicast is counted and produces none; the DNS lookup is a `guest_dns` with exactly the lower-cased name and its type, and five lookups are one event per cycle; the TLS hello is one `guest_tls` per connection with its lower-cased name, protocol and fingerprint; what the audit policy does not list is marked `audit` and is a low detection, what it does list is not, its counters say what would have been dropped and that nothing was; host `tcp_connect` events are still not guest-attributed; vCPU preemption is measured, with a preemptor list that is `[]` and never `null` and a time under 300 seconds; and the VM's KVM exits are still traced.
- **The tripwire checks.** The `vmm` program is attached; the guest's QEMU process is on the kernel's `vmm_watched` map; and a real QEMU raised no tripwire detection while it booted, ran and talked to its peer. Then the real thing: the script asks **this guest's own QEMU**, over its own QMP socket (found on the QEMU command line), to open `/etc/shadow` (a read-only file node, `blockdev-add`, removed again with `blockdev-del`), and requires a **critical `vmm-sensitive-open` detection** naming that VM and attributed to the VMM and not the guest. Nothing is written to the file, and whether QEMU is allowed to open it does not matter, because the tripwire sees the call before the kernel decides. If the QEMU has no QMP socket on its command line the check prints `SKIP` and does not run; look for it in the log.
- **5a.** Only when the daemon has learned [baselines](baselines.md) on with a learning period of five minutes or less (CI's daemon does not): from the fourth cycle the guest uses a network and looks up a site it never had, and the script expects one `new-destination` and one `new-dns-suffix` detection, and none for what it did while learning.
- **5b.** The two guests reach each other (the peer received the message and the guest got the reply); the sender's tap saw a `guest_connect` naming it; the peer's tap saw the same two connections coming in, one accepted and one refused; the guest's accepted connection is in the handshake histogram and none took five seconds; the guest's attempts are accounted for; and the drops program is measuring and lists both taps.
- **5c and 6.** The policy is removed and leaves no orphan; then both VMs are deleted and the tap is no longer traced, the TCX programs are back to the count before, both VMs are gone from the daemon, and the pinned links are back to what they were.

**Why it is safe on a production hypervisor, and what it leaves behind.**

- It creates two VMs and deletes them. Each has a 30-minute TTL as a backstop, so fluxvm removes them even if the script is killed. It never touches another VM and never isolates or releases anything.
- The only policy it applies is an audit-mode egress policy on its own guest. On a host whose fluxvm config has a `[sandbox.dataplane]`, it gives only those two guests a fluxvm policy (private CIDRs, no port restriction) so they can reach each other. The request is repeated for up to a minute, because a VM that has only just been created may not have its network up yet, and a refusal prints its body, which does not contain the token. The token is read from the config, never printed, and kept out of the checks, since a failed check prints its command.
- Its `trap` on exit removes the policy record, deletes both VMs and its temporary directory. A `kill -9` cannot be trapped: the VMs still go when their TTL runs out, but the audit policy record stays until `shukractl policy remove <vm>`.
- It leaves detections behind by design: the low `egress-policy-audit` ones and the critical `vmm-sensitive-open` one all name a `shukra-live-<pid>` VM. Like any detection they are in the daemon's event list and log, and they reach the daemon's alert sinks, so tell whoever watches them.
- It claims a second address, `.202` on the bridge's network (`PEER_IP`), for the peer, and stops if that address is already leased.

It needs the key of the running daemon (`SHUKRA_API_KEY`, which defaults to the one in `/etc/shukra/env`) and `sudo`. The environment is `SHUKRA_URL`, `SHUKRA_API_KEY`, `IMAGE`, `BRIDGE` (default `virbr0`), `PEER_IP`, `FLUXCTL`, `FLUXVM_TOML`, `FLUXVM_URL` and `BOOT_WAIT`. Run it on the hypervisor without putting it on the host first:

```bash
ssh user@hypervisor 'bash -c "$(cat)"' < scripts/test-live-guest.sh
```

(`bash -c "$(cat)"` reads the whole script before running it. `bash -s` lets commands inside the script swallow the rest of it from stdin.)

## The cost of the tap program

`scripts/bench-tap.sh OBJECT [OBJECT...]` is a measurement, not a test. For each object it loads a private copy in its own mount namespace with a fresh bpffs (its own maps, attached to nothing), and times the guest-to-host program with `BPF_PROG_TEST_RUN` on five synthetic packets (a full data segment, an application-data record, a bare ACK, a ClientHello and a UDP datagram). Each figure is the median of five runs of two million (`REPEAT` changes it). Give it the object from before a change and after it: the difference is the honest part, because the same packet run over and over has the warmest caches it will ever have, so read one number as a floor. An object that has the TLS switch is run with it on and off. It needs root, and is safe on a production host. It is how the cost of [TLS server names](tap.md#what-it-costs) and of the [egress policy](egress-policy.md#cost) was measured.

## The console tests

`vitest`, no browser. A component is rendered to a string (`renderToStaticMarkup`) and the string is checked, and everything that decides what a table shows is kept in plain functions so it can be tested without React: `src/eventView.ts` (filter, search, newest-first and paging of the connection tables), `src/explainQuery.ts` (the API paths and file name for a past verdict and an incident bundle), `src/enforce.ts` (what the Isolate page may offer, decided from what the daemon says about enforcement) and `src/hist.ts` (bucket edges and formatting). There are 56 tests in 12 files. What they pin, because each was once wrong on a real host:

- **Nothing the daemon does not know is shown as fact.** No page opens on a made-up VM name (`copy.test.tsx` fails if the fixture name comes back, and the actions, policy and advice pages each have a test that they show nothing made up before the daemon has answered), the sign-in page names the address you connected to and not loopback, and the Overview does not say the tap is missing until it has asked the daemon.
- **A long table never cuts silently.** It shows 50 rows, says how many there are, and offers more (`limited.test.tsx`); an empty result says whether it is the filter or nothing has happened.
- **Nothing is offered that the daemon has not said it can do.** Nothing on the Isolate page may be done until the daemon has said it can enforce, and its wording of what stays reachable and what happens when the daemon stops comes from what the daemon reported, never from what was asked (`enforce.test.ts`). Only a proposal that is still waiting can be decided, and only a policy with a timer running can be confirmed.
- **Data from the API is text, never markup** (`LatencyHist.test.tsx`), and a chart is readable without a pointer: every column says what it is, and the same numbers are in a table.
- **A time is sent as UTC** whatever zone the browser is in. The unit test covers the conversion; running the console under `TZ=Asia/Kolkata` and `TZ=America/Los_Angeles` is checked by hand, not in CI.

Each was checked by mutation: put the old behaviour back and a test fails. `npm test` is `vitest run` and `npm run build` is `tsc --noEmit && vite build`, so the build is also the type-check.

## Continuous integration

Three workflows, in `.github/workflows/`. Each has read-only `contents` permission, except the job of `Release` that publishes, which can write.

| Workflow | Runs | Proves |
|---|---|---|
| `CI` (`ci.yml`) | every push and pull request | Everything below, on `ubuntu-latest`, in one job |
| `Live guest (fluxvm)` (`guest.yml`) | weekly (Monday 04:00 UTC), by hand, and on a pull request that changes `bpf/tap.bpf.c`, `bpf/event.h`, `internal/bpfgen/tap.go`, `internal/observe/tap*.go`, `internal/identity/**`, `scripts/test-live-guest.sh` or the workflow | Two real KVM guests on a runner with `/dev/kvm` |
| `Release` (`release.yml`) | a `v*` tag | The tests again, then the tarball and `.deb` for each architecture |

The `CI` job, step by step:

1. **BPF toolchain.** `clang-18`, `llvm-18`, `libbpf-dev` and the kernel's `bpftool`, linked as `clang`, `llvm-strip` and `bpftool`. The step fails if any of the three is missing.
2. **`make generate`**, and a check that at least one `internal/bpfgen/*_bpfel.go` was written.
3. **`go test -count=1 ./...`**: the stub build, the 528.
4. **`make test-bpf`**: the tagged build and the tap decoder tests.
5. **BPF integration.** Builds the test binary as the runner user and runs only that binary under `sudo` with `SHUKRA_BPF_TEST=1` and `-test.run TestKernelIntegration`: the connect, block and exec checks and the VMM tripwire test, on the runner's real kernel. (`TestKernelPreemption` is not in this step.)
6. **`scripts/test-tap-progrun.sh`**: the egress policy's verdicts, packet by packet.
7. **`scripts/test-tap.sh`**: the rig, all sixteen sections.
8. **`scripts/test-install.sh`**.
9. **Console:** `npm ci` and `npm test`, then `npm run build`.

The `Live guest` job checks out `zyvorai/fluxvm` and `zyvorai/guestkit` beside this repository, makes `/dev/kvm` usable and **fails, rather than skips, if the runner has none**, installs QEMU and libvirt (only for its default network, the `virbr0` bridge with DHCP and NAT), builds `shukrad` with the BPF programs and `fluxctl` from source, caches the Ubuntu cloud image, starts fluxvm, starts `shukrad` on `127.0.0.1:30970` with a fixed key and no rules file, and runs the script. Its path filter names the tap and identity code; a change to `bpf/vmm.bpf.c` or `internal/observe/vmm*.go` does not start it, though the script checks the tripwire, so that check runs on the weekly schedule or by hand. The `Release` job runs `go test`, the console tests and the installer test on both `amd64` (`ubuntu-latest`) and `arm64` (`ubuntu-24.04-arm`) before packaging with `scripts/package.sh`.

The GitHub runners run a newer kernel than most hypervisors, which is a feature: it is where a hard-coded kernel layout breaks first (the drops program failed on Linux 6.9 and newer until it read the tracepoint through the kernel's own type). A green CI is evidence for a kernel the hypervisor may not run, so the live test on the real host is not redundant.

## The rules the tests follow

- **A test must be able to fail.** See [mutation checking](#mutation-checking) below.
- **Exact counts, not "greater than zero".** The rig and the live test assert numbers a kernel can be held to: N connections accepted, N refused, N never answered, and the identity that attempts equal the sum of outcomes. Where a count cannot be exact (a guest that talks for its own reasons while it boots), the check says how far it may be off and why.
- **Never a vacuous check.** A check that passes on stale state (a total with no baseline, a multicast test with no route, a comparison in a window where the guest sent nothing) is treated as a bug. Assertions compare a delta against a baseline taken just before the action, and the live test first checks that the guest sent something in the window.
- **Timing is asserted, not slept past.** Where the kernel needs time (a SYN waits 3 seconds to be called unanswered), the test waits for the documented interval and then reads.
- **A test does not depend on where it runs.** Nothing under `go test ./...` needs Linux, root or a network, and everything that does is behind a build tag or an environment variable, so `make test` is safe on a laptop.

### Mutation checking

Shukra's tests are validated by breaking the code they cover. It is a manual practice, not a tool, and it is how most of the tests above were shown to be worth having: several were written because a mutation survived and exposed a gap. For a new test:

1. Write the test and see it pass.
2. **Break the code under test in the smallest way that should change the behaviour it checks**: invert a comparison, drop a line, swap two arguments, remove a guard. For the console, put the old behaviour back. For a kernel program, edit the `.bpf.c`.
3. Run the test and confirm it goes **red, and for the reason you expect**. A test that goes red for another reason has not shown that it checks the thing.
4. Revert, and confirm it is green again.
5. If it stayed green, the mutation **survived**: the test does not check what you thought. Strengthen it until that mutation is caught.

For the tap program the loop needs no VM. Compile the mutant to its own object and hand it to the packet-by-packet script:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpf -c bpf/tap.bpf.c -o /tmp/tap_mutant.o   # bpf/vmlinux.h comes from `make generate`
sudo scripts/test-tap-progrun.sh /tmp/tap_mutant.o                                            # a check should fail
```

(Use `-D__TARGET_ARCH_arm64` on arm64.) For the `vmm` program, or any per-thread program, edit the C, run `make generate` and then `make test-kernel`. Say in the pull request how many mutations you tried and which were caught; the counts quoted on this page (fifteen for the tripwires, every rule for the egress policy) are from that.

## Verifying BPF changes without a VM

The BPF programs cannot be built or loaded on a Mac, and there is no local VM to load them in. What works:

1. **Write the change, and the tests that run anywhere**: the state, API, CLI, rules and decoder logic. `go test ./...` runs these. A new record gets an untagged decoder and a test (see [development](development.md#extending-what-is-there)).
2. **Type-check the tagged build locally.** The default `go build` skips every file tagged `linux && shukrabpf`, so a compile error in the loaders would only show up on the host. Put a temporary file `internal/bpfgen/zz_tmp_stub.go`, with the same build tag, that defines the seven loaders `bpf2go` would generate:

   ```go
   //go:build linux && shukrabpf

   package bpfgen

   import "github.com/cilium/ebpf"

   func stubSpec() (*ebpf.CollectionSpec, error) { return nil, nil }

   func LoadKvm() (*ebpf.CollectionSpec, error)   { return stubSpec() }
   func LoadSched() (*ebpf.CollectionSpec, error) { return stubSpec() }
   func LoadBlock() (*ebpf.CollectionSpec, error) { return stubSpec() }
   func LoadNet() (*ebpf.CollectionSpec, error)   { return stubSpec() }
   func LoadDrops() (*ebpf.CollectionSpec, error) { return stubSpec() }
   func LoadTap() (*ebpf.CollectionSpec, error)   { return stubSpec() }
   func LoadVmm() (*ebpf.CollectionSpec, error)   { return stubSpec() }
   ```

   then run `GOOS=linux GOARCH=amd64 go vet -tags shukrabpf ./internal/bpfgen ./internal/observe ./cmd/...` and **delete the file**. Nothing ignores it, so make sure it is gone before you commit. A new program adds a loader here; a missing one is `undefined: LoadVmm`.
3. **Check the verdict on a real kernel without touching production.** For the tap program, use a private copy: `unshare -m`, a fresh bpffs, `bpftool prog loadall`, and `bpftool prog run pinned ... data_in FILE repeat N` on hand-built packets, which is what `scripts/test-tap-progrun.sh` and `scripts/bench-tap.sh` do. The copy has its own maps and is attached to nothing, so a running `shukrad` cannot see it and it cannot see the daemon. For a program that hangs off a tracepoint or a kprobe, the kernel integration test is the equivalent: it loads its own unpinned copy and generates the load itself.
4. **Deploy to a real hypervisor and test there:** `./scripts/deploy-remote.sh HOST USER`. The host compiles the CO-RE objects with its own clang and loads them into its real kernel, so a verifier error shows up as a program `detached` with the reason, and the script refuses to install a daemon whose programs did not build unless `SHUKRA_ALLOW_DETACHED=1`. Note that it restarts the service. Then run `scripts/test-live-guest.sh` and read-only `shukractl` checks (`--verify-only` runs only those).
5. **Measure the cost of a hot-path change** (below).
6. **Push, and let CI run the rig and the kernel test** on a real kernel. A rig section is verified by its pull request's CI.

Real-host checks that are safe: the deploy script, the live guest test, read-only `shukractl` and API calls, `bpftool prog show`, `bpftool net`, a few seconds of `bpftrace`, the kernel tests and the packet-by-packet script. Never `isolate` or `release` a VM you did not create, and never run the rig.

### Measuring the cost of a program with `bpf_stats`

For a tap change, `scripts/bench-tap.sh` is the answer. For a tracepoint or kprobe program, which cannot be run on a synthetic packet, use the kernel's own run-time statistics, and compare the old and the new program **at the same time under the same load**; a number from another day is not a comparison.

1. Read `sysctl kernel.bpf_stats_enabled` and remember it. Set it to 1. It is host-wide, it makes the kernel time every BPF program run on the machine, and something else may already have it on, so leave it as you found it.
2. **Record the ids of the programs that exist before you load yours** (`bpftool -j prog show`). A production `shukrad` has its own copy of the same programs on the same hooks, and its `run_time_ns` and `run_cnt` are cumulative from when the statistics were switched on, so they are not yours. After you load, the ids that are new are your copies; read only those, and **exclude the production programs by id**.
3. Load the old and the new program side by side from throwaway test binaries or copies of the tree next to the daemon's, not from the daemon, and hold them for the same interval, long enough on a busy host for the counts to be large.
4. Read `run_time_ns` and `run_cnt` of your new ids twice, at the ends of the interval. **Per call** is the difference in `run_time_ns` over the difference in `run_cnt`. **Share of one core** is the difference in `run_time_ns` over the elapsed nanoseconds. Compare old with new, and scale the per-call figure by the calls per second of the host you care about, since the cost of a program that fires on every open is the host's open rate.
5. To bound the worst case, make every call take the slow path on purpose (the tripwire figures on [its page](vmm-tripwires.md#what-it-costs) were taken with an empty watched list).
6. Set the sysctl back and delete the copies.

## Fixtures

Test fixtures live under `testdata/` and beside the tests: `internal/observe/testdata/tls_hellos.json` (real ClientHellos, above) and `web/src/fixtures.ts` (the console's fake API). `testdata/kubevirt/alpine-quay-fix.vm.backup.yaml` is a KubeVirt `VirtualMachine` kept as it was before its port list was changed: a masquerade interface that declares only port 3389, which is why KubeVirt forwarded nothing else to that guest. No test reads it. It is redacted, because this repository is public: its cloud-init password and the host's address are replaced.
