# Testing

Shukra's claims are about what a real kernel does, so most of its tests load real programs and drive real packets. This page says what each test proves, where it can run, and what is safe to run where. The short version: unit tests run anywhere, the kernel tests need Linux and root, and two of them must **never** run on a hypervisor that is already running Shukra.

## The layers

| Layer | Command | Needs | What it proves |
|---|---|---|---|
| Go unit tests | `make test` (`go test ./...`) | Go 1.25 | Logic: joins, windows, resets, rules, findings, the API, the CLI. Runs on any OS with the stub build |
| Console tests and build | `make web` (`npm test`, `npm run build`) | Node 22 | The console's units, type-check and production build. See [the console tests](#the-console-tests) |
| Loader build | `make test-bpf` | Linux, clang, BTF, `make generate` first | The `shukrabpf` build compiles and its tests pass |
| Kernel integration | `make test-kernel` | Linux, root | Loads the sched, block and net programs into this kernel and checks counters against load the test generates itself: connect counts, block bytes, the exec filter, and vCPU preemption (two CPU-bound threads on one CPU, with a sleeping thread as a control) |
| Tap rig | `make test-tap` (`scripts/test-tap.sh`) | Linux 6.6+, root, `ip`, `curl`, `python3`, `tc`, `iptables` | The tap program, isolation and drops on a real kernel with no KVM. See below |
| Installer | `scripts/test-install.sh` | Linux | The shared install routine, the tarball and the `.deb` lay down the same files |
| Live guest | `make test-live-guest` (`scripts/test-live-guest.sh`) | A hypervisor with fluxvm, `/dev/kvm`, a running `shukrad`, root | Real KVM guests: hot-plug attach, attributed events, packet counts equal to the kernel's, guests reaching each other, handshake outcomes, drops, DNS names, vCPU preemption |

## The rules the tests follow

- **A test must be able to fail.** New tests are checked by *mutation*: break the logic under test and confirm the test goes red. Several tests here were written because a mutation survived and exposed a gap.
- **Exact counts, not "greater than zero".** The rig and the live test assert numbers a kernel can be held to: N connections accepted, N refused, N never answered, and the identity that attempts equal the sum of outcomes.
- **Never a vacuous check.** A check that passes on stale state (a total with no baseline, a multicast test with no route) is treated as a bug. Assertions compare a delta against a baseline taken just before the action.
- **Timing is asserted, not slept past.** Where the kernel needs time (a SYN waits 3 seconds to be called unanswered), the test waits for the documented interval and then reads.

## The console tests

`vitest`, no browser. A component is rendered to a string (`renderToStaticMarkup`) and the string is checked, and everything that decides what a table shows is kept in plain functions so it can be tested without React: `src/eventView.ts` (filter, search, newest-first and paging of the connection tables), `src/explainQuery.ts` (the API paths and file name for a past verdict and an incident bundle), `hist.ts` (bucket edges and formatting). What the tests pin, because each was once wrong on a real host:

- **Nothing the daemon does not know is shown as fact.** No page opens on a made-up VM name (`copy.test.tsx` fails if the fixture name comes back), the sign-in page names the address you connected to and not loopback, and the Overview does not say the tap is missing until it has asked the daemon.
- **A long table never cuts silently.** It shows 50 rows, says how many there are, and offers more (`limited.test.tsx`); an empty result says whether it is the filter or nothing has happened.
- **A time is sent as UTC** whatever zone the browser is in (checked by hand under `TZ=Asia/Kolkata` and `TZ=America/Los_Angeles`, not in CI).

Each was checked by mutation: put the old behaviour back and a test fails. CI runs `npm ci`, the tests and the build.

## The tap rig

`scripts/test-tap.sh` builds a real network path with no KVM. A network namespace stands in for the guest, a veth pair's host end stands in for the tap, and a fake QEMU process names that interface on its command line, so the daemon treats it as a VM's tap. It starts its own `shukrad` on port 30990 with a throwaway data directory.

It has a section per behaviour, each with exact assertions:

1. Isolate is refused without a management allow list.
2. Guest traffic is seen and attributed, over IPv4 and IPv6.
3. Isolation drops what is not allowed and keeps what is, including ping, and release reopens it.
4. Isolation survives a daemon restart, a `kill -9`, a graceful stop, `-detach-all`, and a reboot's lost kernel state.
5. A real `tun` tap: the host's own looped-back frames are not the guest's.
6. UDP flows: one event per flow, none for multicast, IPv6, both rule kinds, isolation dropping UDP.
7. Drops: a real `tc` filter drops the guest's packets and they are counted as `other`; then isolation drops them and they are **not**.
8. TCP handshakes both ways: open, closed, silently dropped, retransmitted and isolated ports, IPv4 and IPv6, with the identity checked exactly.
9. DNS names: case folding, repeats announced once, A and AAAA, IPv6, a name too long for the copy, malformed and non-query packets ignored, a `dns` rule, a blocked query, and `-dns-events=false` and back across daemon restarts.
10. TLS server names: real `openssl` hellos (name, protocols, version, fingerprint), one event per connection, the same client having the same JA3, IPv6, a hello with no name, plain HTTP and malformed records ignored, a long name kept whole, a hello longer than the copy reported cut short with no fingerprint, a `tls` rule, and `-tls-events=false` and back across daemon restarts.

### Never run it on a live hypervisor

The rig and the daemon it starts share the pin directory `/sys/fs/bpf/shukra/tap` with any production `shukrad`, and its cleanup runs `shukrad -detach-all`, which removes **every** pinned link on the host. Run on a machine that is not running Shukra, or in CI. The live guest test is the one that is safe on a working hypervisor.

## The live guest test

`scripts/test-live-guest.sh` boots two disposable Ubuntu cloud images with [fluxvm](https://github.com/zyvorai/fluxvm) on a host bridge (`"netns": false`, so the two guests share L2 and can reach each other): the guest under test and a peer. cloud-init makes the guest send a TCP SYN, twenty UDP datagrams on one flow and three multicast datagrams every 75 seconds, connect to a listener on the peer, connect to a closed peer port, and send hand-built DNS queries (the same name in two spellings, and an AAAA) to an address nothing answers. The script then checks a running daemon against what the kernel says. FluxVM's default per-VM netns, traced on the host veth, is not what this script boots; that mapping is the identity unit tests. See [FluxVM](tap.md#fluxvm).

- What it asserts about DNS and preemption: the lookup arrives as a `guest_dns` event with exactly the lower-cased name and its type, five lookups of one name are one event per 75-second cycle, a hand-built TLS ClientHello to the peer guest arrives as one `guest_tls` event per connection with its lower-cased name, protocol and fingerprint, and the guest's sched row has preemption fields with a preemptor list that is `[]` and never `null` and a time below the VM's lifetime.
- It creates two VMs, gives them a TTL as a backstop, deletes them, and never touches another VM. It never isolates anything.
- Both guests get their own `mac`, since fluxvm gives every tap guest the same default otherwise.
- On a host whose fluxvm config has a `[sandbox.dataplane]`, **only these two guests** get a per-VM policy (private CIDRs, no port restriction) so they can reach each other. The request is repeated for up to a minute, because a VM that has only just been created may not have its network up yet (a 400 on the first try was seen on a real host), and a refusal prints its body, which does not contain the token. The token is read from the config, never printed, and kept out of the checks, since a failed check prints its command.
- Environment: `SHUKRA_URL`, `SHUKRA_API_KEY` (defaults to the key in `/etc/shukra/env`), `IMAGE`, `BRIDGE` (default `virbr0`), `PEER_IP`, `FLUXCTL`, `FLUXVM_TOML`, `FLUXVM_URL`, `BOOT_WAIT`.

Run it on the hypervisor without putting it on the host first:

```bash
ssh sus@hypervisor 'bash -c "$(cat)"' < scripts/test-live-guest.sh
```

(`bash -c "$(cat)"` reads the whole script before running it. `bash -s` lets commands inside the script swallow the rest of it from stdin.)

## Continuous integration

| Workflow | Runs | Proves |
|---|---|---|
| `CI` | every push and pull request | Go and console tests; the programs loaded into the runner's kernel; the tap rig; the installer |
| `Live guest (fluxvm)` | weekly, by hand, and on changes to the tap code, the identity code, the live test or the workflow | Two real KVM guests on a runner with `/dev/kvm`. It fails, rather than skips, when there is no KVM |
| `Release` | a `v*` tag | The tarball and `.deb` for each architecture |

The GitHub runners run a newer kernel than most hypervisors, which is a feature: it is where a hard-coded kernel layout breaks first (the drops program failed there until it read the tracepoint by field name). A green CI is evidence for a kernel the hypervisor may not run, so the live test on the real host is not redundant.

## The kernel test

`TestKernelIntegration` and `TestKernelPreemption` (`internal/observe/integration_bpf_test.go`, tag `shukrabpf`, `SHUKRA_BPF_TEST=1`, root) load the real programs into the running kernel and check what they count against load the test generates itself. Counters are keyed by thread id, so each test locks its goroutine to one OS thread and reads that thread's row: nothing else on the machine can move the numbers, which is what lets the assertions be exact.

`TestKernelPreemption` pins a busy "taker" and a busy "victim" to one CPU. The victim must be charged roughly half the run and the taker must be named by the command the test gave it. A third thread on the same CPU that runs briefly and sleeps is the control: sleeping is not being preempted, so it must not be charged, and removing the runnable check from the program makes the test fail. Unlike the rig, this test loads its own unpinned programs, so it **can** be run on a hypervisor that is running Shukra:

```bash
sudo env "PATH=$PATH" SHUKRA_BPF_TEST=1 go test -tags shukrabpf -run TestKernelPreemption -v ./internal/observe
```

## Verifying BPF changes

The BPF programs cannot be built or loaded on a Mac. The workflow that works:

1. **Write the change, and the tests that can run anywhere**: the state, API, CLI and rules logic. `go test ./...` runs these.
2. **Type-check the tagged build locally.** The default `go build` skips every file tagged `linux && shukrabpf`, so a compile error in the loaders would only show up on the host. Put a temporary file `internal/bpfgen/zz_tmp_stub.go` (same build tag) that defines `LoadKvm`, `LoadSched`, `LoadBlock`, `LoadNet`, `LoadDrops` and `LoadTap` returning `(*ebpf.CollectionSpec, error)`, run `GOOS=linux GOARCH=amd64 go vet -tags shukrabpf ./internal/bpfgen ./internal/observe ./cmd/...`, then delete the file. Add any new generated loader to the stub.
3. **Deploy to a real hypervisor and test there:** `./scripts/deploy-remote.sh HOST USER`. The host compiles the CO-RE objects with its own clang and loads them into its real kernel, so a verifier error shows up as a program `detached` with the reason. Then run `scripts/test-live-guest.sh` and read-only `shukractl` checks.
4. **Measure the cost of a hot-path change.** Turn on `kernel.bpf_stats_enabled`, and compare `run_time_ns` and `run_cnt` of the old and new program **at the same time under the same load** (load both from throwaway test binaries next to the daemon's), then turn it off again and remove the copies. A number from another day is not a comparison.
5. **Push, and let CI run the rig and the kernel test** on a real kernel. A rig section is verified by its pull request's CI, and the queue on GitHub can be slow.

Real-host checks that are safe: the deploy script, the live guest test, read-only `shukractl` and API calls, `bpftool prog show` (it reports `run_time_ns` and `run_cnt` while any process has run-time stats on), and a few seconds of `bpftrace`. Never `isolate` or `release` a VM you did not create.

## Fixtures

Test fixtures live under `testdata/`. `testdata/kubevirt/alpine-quay-fix.vm.backup.yaml` is a KubeVirt `VirtualMachine` kept as it was before its port list was changed: a masquerade interface that declares only port 3389, which is why KubeVirt forwarded nothing else to that guest. It is redacted, because this repository is public: its cloud-init password and the host's address are replaced.
