# Testing

Shukra's claims are about what a real kernel does, so most of its tests load real programs and drive real packets. This page says what each test proves, where it can run, and what is safe to run where. The short version: unit tests run anywhere, the kernel tests need Linux and root, and two of them must **never** run on a hypervisor that is already running Shukra.

## The layers

| Layer | Command | Needs | What it proves |
|---|---|---|---|
| Go unit tests | `make test` (`go test ./...`) | Go 1.25 | Logic: joins, windows, resets, rules, findings, the API, the CLI. Runs on any OS with the stub build |
| Console tests and build | `make web` | Node 22 | The console's units, type-check and production build |
| Loader build | `make test-bpf` | Linux, clang, BTF, `make generate` first | The `shukrabpf` build compiles and its tests pass |
| Kernel integration | `make test-kernel` | Linux, root | Loads the sched, block and net programs into this kernel and checks counters against load the test generates itself: connect counts, block bytes, the exec filter |
| Tap rig | `make test-tap` (`scripts/test-tap.sh`) | Linux 6.6+, root, `ip`, `curl`, `python3`, `tc`, `iptables` | The tap program, isolation and drops on a real kernel with no KVM. See below |
| Installer | `scripts/test-install.sh` | Linux | The shared install routine, the tarball and the `.deb` lay down the same files |
| Live guest | `make test-live-guest` (`scripts/test-live-guest.sh`) | A hypervisor with fluxvm, `/dev/kvm`, a running `shukrad`, root | Real KVM guests: hot-plug attach, attributed events, packet counts equal to the kernel's, guests reaching each other, handshake outcomes, drops |

## The rules the tests follow

- **A test must be able to fail.** New tests are checked by *mutation*: break the logic under test and confirm the test goes red. Several tests here were written because a mutation survived and exposed a gap.
- **Exact counts, not "greater than zero".** The rig and the live test assert numbers a kernel can be held to: N connections accepted, N refused, N never answered, and the identity that attempts equal the sum of outcomes.
- **Never a vacuous check.** A check that passes on stale state (a total with no baseline, a multicast test with no route) is treated as a bug. Assertions compare a delta against a baseline taken just before the action.
- **Timing is asserted, not slept past.** Where the kernel needs time (a SYN waits 3 seconds to be called unanswered), the test waits for the documented interval and then reads.

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

### Never run it on a live hypervisor

The rig and the daemon it starts share the pin directory `/sys/fs/bpf/shukra/tap` with any production `shukrad`, and its cleanup runs `shukrad -detach-all`, which removes **every** pinned link on the host. Run on a machine that is not running Shukra, or in CI. The live guest test is the one that is safe on a working hypervisor.

## The live guest test

`scripts/test-live-guest.sh` boots two disposable Ubuntu cloud images with [fluxvm](https://github.com/zyvorai/fluxvm) on a host bridge: the guest under test and a peer. cloud-init makes the guest send a TCP SYN, twenty UDP datagrams on one flow and three multicast datagrams every 75 seconds, connect to a listener on the peer, and connect to a closed peer port. The script then checks a running daemon against what the kernel says.

- It creates two VMs, gives them a TTL as a backstop, deletes them, and never touches another VM. It never isolates anything.
- Both guests get their own `mac`, since fluxvm gives every tap guest the same default otherwise.
- On a host whose fluxvm config has a `[sandbox.dataplane]`, **only these two guests** get a per-VM policy (private CIDRs, no port restriction) so they can reach each other. The token is read from the config, never printed, and kept out of the checks, since a failed check prints its command.
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

## Verifying BPF changes

The BPF programs cannot be built or loaded on a Mac. The workflow that works:

1. **Write the change, and the tests that can run anywhere**: the state, API, CLI and rules logic. `go test ./...` runs these.
2. **Type-check the tagged build locally.** The default `go build` skips every file tagged `linux && shukrabpf`, so a compile error in the loaders would only show up on the host. Put a temporary file `internal/bpfgen/zz_tmp_stub.go` (same build tag) that defines `LoadKvm`, `LoadSched`, `LoadBlock`, `LoadNet`, `LoadDrops` and `LoadTap` returning `(*ebpf.CollectionSpec, error)`, run `GOOS=linux GOARCH=amd64 go vet -tags shukrabpf ./internal/bpfgen ./internal/observe ./cmd/...`, then delete the file. Add any new generated loader to the stub.
3. **Deploy to a real hypervisor and test there:** `./scripts/deploy-remote.sh HOST USER`. The host compiles the CO-RE objects with its own clang and loads them into its real kernel, so a verifier error shows up as a program `detached` with the reason. Then run `scripts/test-live-guest.sh` and read-only `shukractl` checks.
4. **Push, and let CI run the rig and the kernel test** on a real kernel. A rig section is verified by its pull request's CI, and the queue on GitHub can be slow.

Real-host checks that are safe: the deploy script, the live guest test, read-only `shukractl` and API calls, `bpftool prog show` (it reports `run_time_ns` and `run_cnt` while any process has run-time stats on), and a few seconds of `bpftrace`. Never `isolate` or `release` a VM you did not create.

## Fixtures

Test fixtures live under `testdata/`. `testdata/kubevirt/alpine-quay-fix.vm.backup.yaml` is a KubeVirt `VirtualMachine` kept as it was before its port list was changed: a masquerade interface that declares only port 3389, which is why KubeVirt forwarded nothing else to that guest. It is redacted, because this repository is public: its cloud-init password and the host's address are replaced.
