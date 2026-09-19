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
- **Never guess an identity.** A pid that is not a QEMU thread is `_host`/`unattributed`. A tap no VM owns produces an unattributed event. `guest_attributed` is `true` only for an event seen on a VM's tap that names a VM in the current scan.
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

## Repository layout

See "Where things are" in [architecture](architecture.md).

## Releasing

`make dist` builds a tarball and a `.deb` for this architecture (Linux). Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds both for amd64 and arm64 and attaches them, with checksums, to a GitHub release. `deploy/install.sh` is the one install routine shared by the source deploy, the tarball and the `.deb`.
