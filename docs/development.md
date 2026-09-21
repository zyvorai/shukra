# Developing Shukra

How to build it, how a change goes in, the conventions that keep its promises true, and the steps to add a new eBPF program. Read [architecture](architecture.md) first for how the pieces fit, and [testing](testing.md) for how a change is verified and which tests are safe to run where.

## Build

```bash
make build      # bin/shukrad, bin/shukractl. No BPF: every program reports detached
make web        # console: npm ci, tests, type-check and production build
make test       # go test ./...
```

Linux, with clang, `llvm-strip`, `bpftool` and kernel BTF, also gets the programs:

```bash
make generate                                    # bpf2go: bpf/*.bpf.c -> internal/bpfgen (git-ignored)
CGO_ENABLED=0 go build -tags shukrabpf -o bin/shukrad ./cmd/shukrad
make test-bpf                                    # the tagged build's tests
```

The default build does not link CO-RE objects, so CI on any OS and a Mac stay green. The Linux tag is `shukrabpf`; files that need it carry `//go:build linux && shukrabpf` (or `shukrabpf && linux`), and the `!shukrabpf` stubs beside them keep the default build whole. `make generate` dumps `bpf/vmlinux.h` from the running kernel's BTF, so the objects are built for the architecture and kernel BTF of the machine that runs it. It exits 0 and says it skipped if clang, `llvm-strip`, `bpftool` or BTF is missing; a `-tags shukrabpf` build after that fails because the loaders were never written.

There are **seven programs**: `kvm`, `sched`, `block`, `net`, `vmm`, `drops` and `tap`. `bpf/generate.go` has one `//go:generate` line for each.

## How a change goes in

- **One feature per pull request, each based on `main`.** Do not stack them: a pull request whose base is another feature branch, when merged, updates that branch and not `main`, and the work never lands (this happened to two of them; it was found because `main` lacked a file the merged PR added). If a change needs another that has not merged yet, wait for it, or say so in the description and rebase onto `main` when it has. Do not open a pull request against another feature branch.
- **A change carries its own docs and tests.** A new signal, event, route, command or check is not done until its page, its [signals](signals.md) or [doctor](doctor.md) row, and the CHANGELOG say so. The checklists under [extending what is there](#extending-what-is-there) list the places that have to agree.
- **Shared lines conflict, and that is expected.** When two open pull requests touch the top of the CHANGELOG or the same import, the one that merges second resolves the conflict by keeping both.
- **Say what was verified where, and what was not.** Before opening one, run `go vet ./...`, `go test ./...`, `npm test` and `npm run build` in `web/`, and check that every relative link and heading anchor in the pages you touched resolves (there is no script for that: look). For a BPF change, also run the steps in [verifying BPF changes](testing.md#verifying-bpf-changes-without-a-vm): the tagged type-check, the kernel tests, a deploy and the live guest test. The pull request's own CI is the check for the rig, and the [rig must never be run on a production host](testing.md#never-run-it-on-a-live-hypervisor). The description says which of these you ran and on what, and which you could not.
- **Say how a new test was checked.** A test is only worth having if it can fail, and the way to know is [mutation checking](testing.md#mutation-checking): break the code, watch the test go red, put it back. Say in the description how many mutations you tried and which were caught.

## Conventions that keep the promises true

These are what the docs say Shukra does, and each is enforced by a test:

- **Never invent a number: unmeasured is no row.** A program that is not measuring has no row and no series, not a zero. A VM that no program has measured gets `not_measured`, not "all clear". A metric is omitted, an API field says `measured: false`, and a rule says nothing.
- **Never guess an identity.** A pid that is not a QEMU thread or a FluxVM VMM thread is `_host`/`unattributed`. A tap no VM owns produces an unattributed event. `guest_attributed` is `true` only for an event seen on a VM's host interface that names a VM in the current scan. A FluxVM guest is named from `vms.json`, not invented from a tap name.
- **An empty list is `[]`, never `null`.** Go's nil slice encodes as `null`. Every list in the API goes through `orEmpty`, and a test checks the nested ones too.
- **Windows, not lifetimes.** Anything Explain, doctor or a rule judges is read over a recent window from snapshots, and a counter that went backwards is a reset.
- **Say what you cannot see.** Every signal has a caveat in [signals](signals.md), and Explain's `missing` list is part of its answer.
- **Decode by offset, in a file with no build tag.** A record the kernel writes is read by field offset in an untagged file (`internal/observe/dns.go`, `tls.go`, `vmm.go`, `decode.go`), so the decoder is unit-tested on any OS, and a record that is too short, the wrong size or of an unknown kind is counted as lost and never guessed at. The Go constant for a record's size must match the `_Static_assert` beside the C struct.
- **Add a new map; never change a pinned map's layout.** The tap program's maps are pinned, which is what lets isolation survive an upgrade. A changed layout forces the old pins to be replaced, with a gap in enforcement. Add a new map, or spend a spare byte of an existing value (the egress mode is the second byte of `tap_policy`'s value, which always had seven spare).
- **Sanitise every byte a guest or a VMM chose.** A name, path or command that came from a packet or from a VMM's process tree is made printable (every byte that is not printable ASCII becomes `?`), bounded, and lower-cased where case does not matter, before it can reach a log, a terminal, JSON or a rule. `parseQName` (`dns.go`), `printable` (`tls.go`) and `printablePath` (`vmm.go`) are the models. A guest chooses the bytes it sends. The command names of host tasks (the `comm` of an exec event, and the preemptor list) are kept as the kernel reported them, up to 16 bytes, and are not made printable today; do not put one in front of a terminal without doing so.
- **A guest controls its own traffic, so bound everything it can fill.** Any table keyed by packet contents (flows, pending SYNs) is a fixed-size LRU, and events are rate-limited on their own budget, so a guest can turn tables over but cannot grow them or flood the ring.
- **Return `TCX_NEXT`, never `TCX_PASS`.** `TCX_PASS` ends the chain and would skip Cilium and any other program on the tap.
- **Enforcement fails closed, and lifting it is deliberate.** A crash leaves isolation and an enforcing policy in place. What lifts one is a person (`release`, `policy remove`, `shukrad -detach-all`) or a timer that was set when it was applied.

## Adding a program

Copy `block` (a tracepoint or kprobe program with per-thread histograms), `vmm` (a tracepoint program that reports events, is judged in the daemon and has an off switch) or `drops` (a per-interface program with its own precondition). The steps, in order:

1. **The program.** `bpf/<name>.bpf.c`. The first line is `//go:build ignore`. Include `vmlinux.h`, `<bpf/bpf_helpers.h>` and, if it reads kernel structs, `<bpf/bpf_core_read.h>`. Give its maps a program prefix (`vmm_events`, `tap_stats`): the sampler runs every `read…` function over every collection's maps by name, so a map called `sched_stats` in a new program would be read as the scheduler's. (`sched`, `block` and `net` each have a map called `events`, which works only because each collection is read on its own.) Use `SEC("tracepoint/group/name")` or `SEC("kprobe/symbol")`: `attachSection` supports only those two, and fentry and `tp_btf` need a new branch. **Read tracepoint records through the kernel's own type** (`struct trace_event_raw_<name>` from vmlinux BTF) so it survives layout changes between kernels. Hand-laid records are for tracepoints that BTF does not describe, like KVM on 6.8. A program that attaches only some of its hooks reports `attached` with `N/M hooks` and the error in its detail, so read the detail.
2. **The generator.** One `//go:generate` line in `bpf/generate.go`, then `make generate` on Linux.
3. **The loader.** `try("<name>", Load<Name>)` in `internal/bpfgen/attach.go`, or `tryUnlessDisabled` if it has an off switch (`bpfgen.Disable` before `Attach`, as `-vmm-tripwires=false` does). If it needs a check before it can run (a kernel feature), put that in its own function that reports `detached` with the reason in words, as `drops` does. **Add the new `Load<Name>` to the local type-check stub** ([verifying BPF changes](testing.md#verifying-bpf-changes-without-a-vm)): without it the tagged build is `undefined: Load<Name>`.
4. **The sampler.** A `read<Name>` function in `internal/observe/sample_bpf.go` and a call in `Sample()`, or a `<Name>Sample()` if it is keyed by interface rather than thread. If it emits events, a `Start<Name>` that reads its ring with a decoder from an untagged file, started in `internal/agent/agent.go` beside `StartTap` and `StartVMM`. If it must know which processes are VMMs, feed it from `SetWatched`. Add the program to `programs_bpf.go` (its error fallback list), `programs_stub.go` and the default list in `state.New`. Anything exported needs a stub in the `!shukrabpf` file for its area (`sample_stub.go`, `tap_stub.go`, `drops_stub.go`).
5. **The counters.** For per-thread data, add fields to `aggregate.Counters` and to **all** of `add`, `Delta` and `Clone` (a field missed in `Delta` reads zero in every window, silently). Add a row type with a `Measured` flag and a getter like `aggregate.Block`. Per-interface data follows `internal/state/drops.go`.
6. **The state.** A getter on `State`, snapshots in `history.go` if it is windowed, and Explain and doctor findings where they help.
7. **The API and metrics.** A route in `internal/api/server.go` using `orEmpty`, and a `Measured`-gated block in `metrics.go`.
8. **The CLI and console.** `traceCmd`, `formatTraceList`, `formatTrace` in `cmd/shukractl`, and the page, nav entry, hero and fixture in `web/src`.
9. **The tests.** Unit tests for everything above; an untagged decode test if it emits events; a section in `scripts/test-tap.sh` if it involves the tap, or a kernel integration test (`SHUKRA_BPF_TEST`, one thread pinned, exact counts) if it is per-thread. Check each new test by mutation.
10. **The cost.** Measure it and put the number, and how it was taken, in the guide. See [measuring the cost of a program](testing.md#measuring-the-cost-of-a-program-with-bpf_stats).
11. **The docs.** A row in [signals](signals.md) with its caveat, the series, and a guide if it answers a question of its own (see [drops](drops.md) and [VMM tripwires](vmm-tripwires.md)).

The unit needs no new capability for a tracing program: `CAP_BPF` and `CAP_PERFMON` cover tracepoints and kprobes.

## Extending what is there

Most changes are not a new program. Each of these is a checklist of the places that have to agree, and the test that catches a missed one.

### A new event kind

1. `internal/event/event.go`: the `Kind` constant and any new fields (`omitempty`, so old consumers are unaffected).
2. The producer: a ring record decoded **by offset** in an untagged file (as `internal/observe/dns.go` does), so the decoder is unit-tested on any OS, and never trusted: a record that does not decode is counted as lost, not guessed at. A guest controls what it sends, so anything taken from a packet is sanitised (`dns.go` turns every unprintable byte into `?`).
3. `internal/agent/agent.go`: a guest event is added to the list in `Ingest` that sends it to `ingestGuest`, with `connectRules` saying which rules apply to it. An event that is not a guest's, like the VMM tripwire's, gets its own ingest (`ingestVMM` in `internal/agent/vmm.go`) that joins it to its VM and says whose it is.
4. Surfaces: the console's filter in `web/src/pages/Traces.tsx`, `printEvent` in `cmd/shukractl/commands.go`, the event table in [API](api.md).
5. A guest cannot be allowed to flood it. Give it its own rate limit and de-duplication in the kernel program, so it cannot starve another kind of event.

### A new detection rule type

The file is read strictly, so a misspelled key is an error and not a silently disabled rule. Add the field to `doc` and the rule struct in `internal/detect/config.go`, validate it in `Parse` (severity, a repeated name, exactly one match kind), add a `Match…` method, apply it in `internal/agent/agent.go` with a suppression key that includes what makes two alerts different, and add it to `configs/detections.example.yaml`. `TestShippedExampleParses` uncomments every example and parses it, so it fails until the example and the test agree.

### A new threshold metric

A constant and an entry in `metrics` (`internal/detect/config.go`), a field in `vmSnap` filled in `snap()`, and a `case` in `metric()` in `internal/detect/threshold.go`. **Say nothing when the measurement was not on**, at either end of the window: return `false`, never zero, or a rule like `>= 0` fires on a program that is off. Add it to the table in [tutorial 6](tutorials/06-watchlist.md).

### A new Explain cause

In `diagnose` (`internal/state/verdict.go`), from windowed rows (`Delta`), with constants for the floor and the confidence lines, and evidence that names numbers from the window. A finding that cannot name its evidence is not a finding. Add the cause to the list in [tutorial 4](tutorials/04-shukractl.md) and, if the question needs its own page, a guide.

### A new view: an API route, the CLI and a console page

The pattern that `contention` and `explain --at` followed. The logic lives in `internal/state` and returns plain structs whose lists are never nil. Then:

1. **The route** in `internal/api/server.go`, with `orEmpty` (or an explicitly non-nil list) for every list, and its own argument parsing that returns `400` with a sentence. A test asserts the empty response has `[]`, not `null`. A route that changes anything is not a `GET`: the read-only key is refused every other method.
2. **The CLI**: a `case` in `run` (or a kind in `traceCmd`), a `format…` function, a line in `help.go`, and a test that checks the query string it sends (times are escaped: a `+` in a zone offset must not become a space) and the text it prints.
3. **The console page**: a `Page` in `components/Nav.tsx`, an entry in `pages` and `heroes` and the body map in `App.tsx`, the component, a fixture route in `fixtures.ts`, and a test of what it says when there is nothing.
4. **The docs**: [API](api.md), [shukractl](shukractl.md), the console tutorial, the README's endpoint table, and the CHANGELOG.

### A new doctor check

An `add(id, status, title, detail, fix)` in `internal/state/doctor.go`, with the fix in words an operator can act on, and a row in [doctor](doctor.md). A check reads state and never probes.

### A change to the tap program

Never change an existing pinned map's layout: add a new map, or old pins are replaced with a gap in enforcement. Decide for each new map whether it must be **pinned** (the running program and the next daemon must share it: an on/off switch, a ring, a policy) or not (keyed by values the guest controls, so it should not outlive a restart: `udp_flows`, `pending_syn`, `dns_seen`, `tls_flows`, `egress_udp_in`). A record that is read by offset carries a `_Static_assert` on its size, and the Go decoder's constant must match. Every packet on every VM's tap runs through it, so measure a change with `scripts/bench-tap.sh` on the object from before and after, and check a policy change packet by packet with `scripts/test-tap-progrun.sh`. Neither needs a VM, and both are safe on a production host.

## Kernel verifier lessons

The verifier accepts a program only if it can prove every access is safe, and it proves less than you think. What has gone wrong, and what fixed it:

- **Build a length's bounds by arithmetic on a 64-bit value.** A length passed to a helper such as `bpf_skb_load_bytes` must have a provable lower bound. A comparison against zero on a 32-bit value does not give the verifier one, and it reports `invalid zero-sized read`. Build the bound by arithmetic on a `__u64`: `m = have - 1; if (m > MAX - 1) m = MAX - 1; have = m + 1;`, so `m` is provably `0` to `MAX - 1` and `have` is `1` to `MAX`. The DNS and TLS parsers in `tap.bpf.c` both do exactly this.
- **Reserve ring buffer space and write into it directly.** The BPF stack is 512 bytes. A 1504-byte TLS hello (`TLS_RAW`) cannot be built on it and copied, so `tls_hello` reserves a record with `bpf_ringbuf_reserve`, loads the packet straight into `e->raw`, and discards the record if the load fails. (A 128-byte DNS question does fit on the stack, and is copied.) Reserve first, fill in place, then submit.
- **Clear only the header of a large record.** Reserved ring memory is not zeroed, so the fixed fields must be, but the payload can be 1.5 KB and only `rawlen` bytes of it are ever read. `memset` up to `offsetof(struct tls_event, raw)`, not the whole record (`vmm_begin` does the same before the path). The daemon must in turn read only the bytes the length field claims, and a test pins that.
- **Keep register pressure low.** A BPF program has eleven registers, one of them the read-only frame pointer, and a helper call clobbers `r1` to `r5`, so only `r6` to `r9` survive one. A function that keeps more values than that alive across a call makes the compiler spill the rest to a stack that is 512 bytes, and a spilled value can come back with less than the verifier had proved about it. So carry as little as you can across a helper call: pass a pointer to an address rather than copies of it (the `const __u8 *src, *dst` arguments in `tap.bpf.c`), finish with a value before the next call instead of holding it, and put what only some packets need in its own `__always_inline` function that returns early. If a change makes a program that loaded stop loading, look first at what it now keeps alive across a call.
- **Constant sizes for copies.** `__builtin_memcpy` of a fixed 4 or 16 bytes, chosen by family, is provable; a length in a variable is not until you bound it as above.
- **When a parse can be done in userspace, do it there.** The kernel side of DNS only checks the header and copies the question; the name, the TLS extensions and the fingerprint are decoded in the daemon, where they can be unit-tested and cannot upset the verifier.
- **Read a tracepoint record by field name.** A record read as `struct trace_event_raw_<name>` survives kernel changes; a hard-coded offset does not. The drops program failed on Linux 6.9 and newer until it read `kfree_skb` this way.
- **Test on the kernel you will run on, and on a newer one.** The verifier changes between releases. CI's runner is newer than most hypervisors, and a deploy is the only way to know a real one accepts the program; see [verifying BPF changes](testing.md#verifying-bpf-changes-without-a-vm).

## Releasing

`make dist` builds a tarball and a `.deb` for this architecture (Linux). It needs clang, `bpftool` and kernel BTF, since the CO-RE objects are compiled into `shukrad`; the result needs only kernel BTF to run. `scripts/package.sh` refuses to package a daemon that was not built with `-tags shukrabpf`, since it would install and then report every program detached.

Pushing a `v*` tag runs `.github/workflows/release.yml`. For each of `amd64` (on `ubuntu-latest`) and `arm64` (on `ubuntu-24.04-arm`), it installs the BPF toolchain, runs `go test`, the console tests and the installer test, runs `scripts/package.sh` with the tag as the version, builds a container image of that binary, and uploads the tarball, `.deb`, image and checksums. The image's default command listens on loopback; publishing the port means replacing that command, with TLS or with `-allow-insecure-http` behind a TLS proxy ([v0.1.0](releases/v0.1.0.md)). A last job writes a CycloneDX SBOM of those files. If the repository secret `COSIGN_PRIVATE_KEY` is set, that job also signs each file with cosign and writes an attestation; a signing failure fails the release. `COSIGN_PASSWORD` is the key's password when the key is encrypted. Leave the private key unset to publish without signatures. After a release is downloaded, `scripts/verify-release.sh` checks each `.sha256`, that `shukra.cdx.json` is a CycloneDX document, and any `cosign` signatures that were published. Signatures are required only when `SHUKRA_REQUIRE_SIGNATURES=1`. The two architectures are built on their own runners because the objects are compiled against the build machine's kernel BTF and CO-RE then lets the same binary run on other kernels of that architecture. The version is stamped into both binaries with `-X github.com/zyvorai/shukra/internal/version.Version`. Guest traffic requires Linux 6.6+ (TCX). Kernels older than that are not a release test: the tap program stays detached and the host probes still run.

`deploy/install.sh` is the one install routine shared by the source deploy (`scripts/deploy-remote.sh`), the tarball and the `.deb`; `scripts/test-install.sh` tests it. Do not push the `v0.1.0` tag until the notes in [v0.1.0](releases/v0.1.0.md) match the commit you are tagging. [the CHANGELOG](../CHANGELOG.md) lists what has merged to `main`, newest first.

CI (`.github/workflows/ci.yml`) runs the tests, a race-detector pass, `go vet`, `staticcheck`, a pinned `govulncheck`, short fuzz targets, `npm audit`, and an arm64 job that runs the Go and console tests without loading BPF. Coverage is uploaded as an artifact and is not a merge gate. Guest traffic is TCX on Linux 6.6+; the tap rig on the current runner is that test. Older kernels are not a matrix and not a supported guest datapath.

## Repository layout

See "Where things are" in [architecture](architecture.md).
