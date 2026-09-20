# Developing Shukra

How to build it, how the code is laid out, the conventions that keep its promises true, and the steps to add a new eBPF program. Read [architecture](architecture.md) first for how the pieces fit, and [testing](testing.md) for how a change is verified.

## Build

```bash
make build      # bin/shukrad, bin/shukractl. No BPF: every program reports detached
make web        # console tests, type-check and production build
make test       # go test ./...
```

Linux, with clang, `bpftool` and kernel BTF, also gets the programs:

```bash
make generate                                    # bpf2go: bpf/*.bpf.c -> internal/bpfgen (git-ignored)
CGO_ENABLED=0 go build -tags shukrabpf -o bin/shukrad ./cmd/shukrad
```

The default build does not link CO-RE objects, so CI on any OS and a Mac stay green. The Linux tag is `shukrabpf`. `make generate` exits 0 and says it skipped if clang or BTF is missing; a `-tags shukrabpf` build after that fails because the loaders were never written.

## Conventions that keep the promises true

These are what the docs say Shukra does, and each is enforced by a test:

- **Never invent a number.** A program that is not measuring has no row and no series, not a zero. A VM that no program has measured gets `not_measured`, not "all clear". A metric is omitted, an API field says `measured: false`, and a rule says nothing.
- **Never guess an identity.** A pid that is not a QEMU thread or a FluxVM VMM thread is `_host`/`unattributed`. A tap no VM owns produces an unattributed event. `guest_attributed` is `true` only for an event seen on a VM's host interface that names a VM in the current scan. A FluxVM guest is named from `vms.json`, not invented from a tap name.
- **An empty list is `[]`, never `null`.** Go's nil slice encodes as `null`. Every list in the API goes through `orEmpty`, and a test checks the nested ones too.
- **Windows, not lifetimes.** Anything Explain, doctor or a rule judges is read over a recent window from snapshots, and a counter that went backwards is a reset.
- **Say what you cannot see.** Every signal has a caveat in [signals](signals.md), and Explain's `missing` list is part of its answer.
- **Never change a pinned map's layout.** The tap program's maps are pinned, which is what lets isolation survive an upgrade. Add a new map instead. A changed layout forces the old pins to be replaced, with a gap.
- **Return `TCX_NEXT`, never `TCX_PASS`.** `TCX_PASS` ends the chain and would skip Cilium and any other program on the tap.
- **A guest controls its own traffic.** Any table keyed by packet contents (flows, pending SYNs) is a fixed-size LRU, and events are rate-limited, so a guest can turn tables over but cannot grow them or flood the ring.

## Adding a program

Copy `block` (a tracepoint or kprobe program with per-thread histograms) or `drops` (a per-interface program). The steps, in order:

1. **The program.** `bpf/<name>.bpf.c`. The first line is `//go:build ignore`. Include `vmlinux.h`, `<bpf/bpf_helpers.h>` and, if it reads kernel structs, `<bpf/bpf_core_read.h>`. Give its maps a program prefix, since userspace looks maps up by name across all programs. Use `SEC("tracepoint/group/name")` or `SEC("kprobe/symbol")` (the loader supports only those two; fentry and `tp_btf` need a new branch in `attachSection`). **Read tracepoint records through the kernel's own type** (`struct trace_event_raw_<name>` from vmlinux BTF) so it survives layout changes between kernels. Hand-laid records are for tracepoints that BTF does not describe, like KVM on 6.8.
2. **The generator.** One `//go:generate` line in `bpf/generate.go`, then `make generate` on Linux.
3. **The loader.** `try("<name>", Load<Name>)` in `internal/bpfgen/attach.go`. If it needs a check before it can run (a kernel feature), put that in its own function that reports `detached` with the reason in words, as `drops` does.
4. **The sampler.** A `read<Name>` function in `internal/observe/sample_bpf.go` and a call in `Sample()`, or a `<Name>Sample()` if it is keyed by interface rather than thread. Add the program to `programs_bpf.go`, `programs_stub.go` and `state.New`. Anything exported needs a stub in `sample_stub.go`.
5. **The counters.** For per-thread data, add fields to `aggregate.Counters` and to **all** of `add`, `Delta` and `Clone` (a field missed in `Delta` reads zero in every window, silently). Add a row type with a `Measured` flag and a getter like `aggregate.Block`. Per-interface data follows `internal/state/drops.go`.
6. **The state.** A getter on `State`, snapshots in `history.go` if it is windowed, and Explain and doctor findings where they help.
7. **The API and metrics.** A route in `internal/api/server.go` using `orEmpty`, and a `Measured`-gated block in `metrics.go`.
8. **The CLI and console.** `traceCmd`, `formatTraceList`, `formatTrace` in `cmd/shukractl`, and the page, nav entry, hero and fixture in `web/src`.
9. **The tests.** Unit tests for everything above; a decode test if it emits events; a section in `scripts/test-tap.sh` if it involves the tap, or the kernel integration test if it is per-thread. Check each new test by mutation.
10. **The docs.** A row in [signals](signals.md) with its caveat, the series, and a guide if it answers a question of its own (see [drops](drops.md)).

The unit needs no new capability for a tracing program: `CAP_BPF` and `CAP_PERFMON` cover tracepoints and kprobes.

## Extending what is there

Most changes are not a new program. Each of these is a checklist of the places that have to agree, and the test that catches a missed one.

### A new event kind

1. `internal/event/event.go`: the `Kind` constant and any new fields (`omitempty`, so old consumers are unaffected).
2. The producer: a ring record decoded **by offset** in an untagged file (as `internal/observe/dns.go` does), so the decoder is unit-tested on any OS, and never trusted: a record that does not decode is counted as lost, not guessed at. A guest controls what it sends, so anything taken from a packet is sanitised (`dns.go` turns every unprintable byte into `?`).
3. `internal/agent/agent.go`: add the kind to the list in `Ingest` that sends guest events to `ingestGuest`, and say in `connectRules` which rules apply to it.
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

1. **The route** in `internal/api/server.go`, with `orEmpty` (or an explicitly non-nil list) for every list, and its own argument parsing that returns `400` with a sentence. A test asserts the empty response has `[]`, not `null`.
2. **The CLI**: a `case` in `run` (or a kind in `traceCmd`), a `format…` function, a line in `help.go`, and a test that checks the query string it sends (times are escaped: a `+` in a zone offset must not become a space) and the text it prints.
3. **The console page**: a `Page` in `components/Nav.tsx`, an entry in `pages` and `heroes` and the body map in `App.tsx`, the component, a fixture route in `fixtures.ts`, and a test of what it says when there is nothing.
4. **The docs**: [API](api.md), [shukractl](shukractl.md), the console tutorial, the README's endpoint table, and the CHANGELOG.

### A new doctor check

An `add(id, status, title, detail, fix)` in `internal/state/doctor.go`, with the fix in words an operator can act on, and a row in [doctor](doctor.md). A check reads state and never probes.

### A change to the tap program

Never change an existing pinned map's layout: add a new map, or old pins are replaced with a gap in enforcement. Decide for each new map whether it must be **pinned** (the running program and the next daemon must share it: an on/off switch, a ring) or not (keyed by values the guest controls, so it should not outlive a restart). A record that is read by offset carries a `_Static_assert` on its size, and the Go decoder's constant must match.

### Kernel verifier lessons

- A length passed to a helper such as `bpf_skb_load_bytes` must have a provable lower bound. A comparison against zero on a 32-bit value does not give the verifier one, and it reports `invalid zero-sized read`. Build the bound by arithmetic on a 64-bit value: `m = have - 1; if (m > MAX - 1) m = MAX - 1; have = m + 1;`.
- When a parse can be done in userspace, do it there. The kernel side of DNS only checks the header and copies the question.
- A tracepoint record read by field name (`struct trace_event_raw_<name>`) survives kernel changes. A hard-coded offset does not.

## Pull requests

One feature per pull request, each based on `main`. **Do not stack them**: a pull request whose base is another feature branch, when merged, updates that branch and not `main`, and the work never lands (this happened to two of them; it was found because `main` lacked a file the merged PR added). If a change needs another that has not merged yet, wait for it, or say so in the description and rebase when it has. When two open pull requests touch the top of the CHANGELOG or the same import, the one that merges second resolves the conflict by keeping both.

Before opening one: `go vet ./...`, `go test ./...`, `npm test` and `npm run build` in `web/`, the docs link check, and, for a BPF change, the deploy and the live guest test described in [testing](testing.md). Say in the description what was verified where, and what was **not**.

## Repository layout

See "Where things are" in [architecture](architecture.md).

## Releasing

`make dist` builds a tarball and a `.deb` for this architecture (Linux). Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds both for amd64 and arm64 and attaches them, with checksums, to a GitHub release. `deploy/install.sh` is the one install routine shared by the source deploy, the tarball and the `.deb`.
