# Attach traces

`shukrad` only loads eBPF when three things are true: the binary was built with `-tags shukrabpf`, the host has kernel BTF, and the process can attach tracepoints. The default `make build` skips all of that on purpose, so a Mac and CI do not pretend to be attached.

## What the host needs

- Linux with `/sys/kernel/btf/vmlinux` readable
- `clang` and `llvm-strip`
- `bpftool` (so `make generate` can write `bpf/vmlinux.h`)
- Root, or the capabilities the shipped unit grants: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN` (to attach the tap program) and, to read libvirt VMs' taps, `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`
- A kernel new enough for what you want: any program needs `CAP_BPF` (Linux 5.8+); `drops` needs 5.17+; the `tap` program needs 6.6+ (TCX). A program the kernel cannot support reports itself `detached` with the reason, and the others still run

Check:

```bash
test -r /sys/kernel/btf/vmlinux && echo btf=yes
command -v clang
command -v llvm-strip
command -v bpftool
uname -r
```

You should get `btf=yes`, three paths and a kernel version. Anything missing makes `make generate` skip (below).

KVM trace records are not in vmlinux BTF on Ubuntu 6.8, so the `kvm` program uses the tracepoint format directly (`exit_reason` is the first field after the 8-byte common header). The scheduler, block and TCP programs use BTF types. The `drops` program reads `skb:kfree_skb` through the kernel's own BTF description of the record, so it survives layout changes between kernels (Linux 6.9 moved the fields). The `vmm` program reads the syscall tracepoints through the kernel's own `trace_event_raw_sys_enter`.

## Generate and build

From the repo root, on that Linux host:

```bash
make generate
CGO_ENABLED=0 go build -tags shukrabpf -o bin/shukrad ./cmd/shukrad
CGO_ENABLED=0 go build -o bin/shukractl ./cmd/shukractl
```

`make generate` runs bpf2go into `internal/bpfgen`, for the architecture you run it on (`go generate` sets `$GOARCH`). `bpf/vmlinux.h` is dumped from that machine's kernel BTF and differs per architecture, so generate on the host you will run on, or on one of the same architecture. Those files are build products. Do not commit `bpf/vmlinux.h`.

If `clang`, `llvm-strip`, `bpftool` or BTF is missing, `make generate` exits 0 and prints which one (`clang not found; skipping generate`). The following `go build -tags shukrabpf` will then fail, because the loaders were never written. Build without the tag instead. Programs stay detached, which is the honest result.

You should see `make generate` finish with no `skipping` line, and `ls internal/bpfgen/*_bpfe*.go` list generated files for each of `kvm`, `sched`, `block`, `net`, `drops`, `tap` and `vmm`.

## Run

```bash
sudo ./bin/shukrad -listen 127.0.0.1:30970 -web web/dist -watchlist configs/detections.example.yaml
```

```bash
./bin/shukractl programs
```

You want `attached` and a hook count, not a counter you did not ask for. Eight programs:

```text
PROGRAMS
  kvm       attached    4 hooks
  sched     attached    4 hooks
  block     attached    3 hooks
  mem       attached    3 hooks
  net       attached    3 hooks
  vmm       attached    15 hooks
  drops     attached    1 hooks
  tap       attached    9 taps via tcx, enforcement survives a daemon restart   # 9 is however many VM taps are up
```

`shukractl status` says `programs    8/8 attached` when all are.

`tap` reports `detached` with `no VM tap interfaces to attach to yet` until a VM with a tap is running, then `attached` with how many. That is a state of the host, not a fault.

`net` has three hooks: `tcp_v4_connect`, `tcp_v6_connect` and the retransmit tracepoint. `vmm` has fifteen: the `openat`, `openat2` and `open` entry points, ten syscalls a VMM never makes (`ptrace`, `mount`, `unshare` and the like) and a fork and an exit hook that keep its table of descendants. On arm64 `kvm` reports `3/4 hooks` because `kvm_pio` does not exist there, and a program that attaches only some of its hooks says `N/M hooks` with the error for the last one it could not attach. `vmm` is on by default and is the only program you can leave out on purpose: `-vmm-tripwires=false` reports it `detached` with `turned off with -vmm-tripwires=false`. What each program records, and where it is only bucketed or unproven, is in [signals](../signals.md); what `vmm` reports is [tutorial 11](11-vmm-tripwires.md).

Confirm the kernel still has them after the CLI returns. The daemon keeps the links for the life of the process. A second `shukractl programs` a few seconds later should still say attached. For `kvm`, `sched`, `block`, `net`, `vmm` and `drops`, if the process exits the hooks go with it. The `tap` program is different on purpose: its links and maps are pinned under `/sys/fs/bpf/shukra/tap`, so an isolated VM, or one under an enforcing egress policy, stays that way when the daemon stops (see [guest traffic and isolation](../tap.md) and [egress policy](10-egress-policy.md)).

If a VM is running, one more check that the numbers are real:

```bash
shukractl vms
shukractl trace kvm
```

`trace kvm` lists exit, entry, MMIO and PIO counters for each VM, and the counts should go up between two runs. On a host with no VM it says `no rows`. A number that stays at zero for a VM that is busy means the program is not measuring it: `shukractl explain <vm>` says so in its `missing` list and does not guess.

## What "attached" is not

Attached means the tracepoint or kprobe is live. It does not mean a guest has been named. `shukractl trace net` is still the QEMU process. Read [attribution](../attribution.md) before you brief anyone with a packet.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `make generate` prints `skipping generate` | The tool it names is missing. Install it, or build without the tag and accept detached programs |
> | `go build -tags shukrabpf` fails with undefined `LoadKvm` (or another `Load...`) | The loaders were never generated. Run `make generate` again and read what it printed |
> | A program is `detached` with `operation not permitted` | Run as root, or with the capabilities above. `tap` needs `CAP_NET_ADMIN` |
> | A program is `detached` with a verifier error | The kernel refused the object. `shukractl doctor` and the daemon's log carry the error. The other programs still run. Report the kernel version and the text |
> | `tap` says `TCX needs Linux 6.6 or newer` | The kernel is older. Guest traffic is not supported there. Everything else works, and `doctor` says so |
> | `drops` is `detached` on Linux older than 5.17 | Expected: it needs the drop reason |
> | `tap` is `detached` with `no VM tap interfaces to attach to yet` | Expected until a VM with a tap runs |

Next: [deploy this onto a hypervisor](03-deploy.md) so you are not building by hand.
