# Attach traces

`shukrad` only loads eBPF when three things are true: the binary was built with `-tags shukrabpf`, the host has kernel BTF, and the process can attach tracepoints. The default `make build` skips all of that on purpose, so a Mac and CI do not pretend to be attached.

## What the host needs

- Linux with `/sys/kernel/btf/vmlinux` readable
- `clang`
- `bpftool` (so `make generate` can write `bpf/vmlinux.h`)
- Root, or the capabilities the shipped unit grants: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN` (to attach the tap program) and, to read libvirt VMs' taps, `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`
- A kernel new enough for what you want: any program needs `CAP_BPF` (Linux 5.8+); `drops` needs 5.17+; the `tap` program needs 6.6+ (TCX). A program the kernel cannot support reports itself `detached` with the reason, and the others still run

Check:

```bash
test -r /sys/kernel/btf/vmlinux && echo btf=yes
command -v clang
command -v bpftool
```

KVM trace records are not in vmlinux BTF on Ubuntu 6.8, so the `kvm` program uses the tracepoint format directly (`exit_reason` is the first field after the 8-byte common header). The scheduler, block and TCP programs use BTF types. The `drops` program reads `skb:kfree_skb` through the kernel's own BTF description of the record, so it survives layout changes between kernels (Linux 6.9 moved the fields).

## Generate and build

From the repo root, on that Linux host:

```bash
make generate
CGO_ENABLED=0 go build -tags shukrabpf -o bin/shukrad ./cmd/shukrad
CGO_ENABLED=0 go build -o bin/shukractl ./cmd/shukractl
```

`make generate` runs bpf2go into `internal/bpfgen`, for the architecture you run it on (`go generate` sets `$GOARCH`). `bpf/vmlinux.h` is dumped from that machine's kernel BTF and differs per architecture, so generate on the host you will run on, or on one of the same architecture. Those files are build products. Do not commit `bpf/vmlinux.h`.

If clang or BTF is missing, `make generate` exits 0 and prints that it skipped. The following `go build -tags shukrabpf` will then fail, because the loaders were never written. Build without the tag instead. Programs stay detached, which is the honest result.

## Run

```bash
sudo ./bin/shukrad -listen 127.0.0.1:30970 -web web/dist -watchlist configs/detections.example.yaml
```

```bash
./bin/shukractl programs
```

You want `attached` and a hook count, not a counter you did not ask for:

```text
kvm       attached    4 hooks
sched     attached    4 hooks
block     attached    2 hooks
net       attached    3 hooks
drops     attached    1 hooks
tap       attached    9 taps, enforcement survives a daemon restart
```

`tap` reports `detached` with `no VM tap interfaces to attach to yet` until a VM with a tap is running, then `attached` with how many. That is a state of the host, not a fault.

`net` has three hooks: `tcp_v4_connect`, `tcp_v6_connect` and the retransmit tracepoint. On arm64 `kvm` reports `3/4 hooks` because `kvm_pio` does not exist there. What each program records, and where it is only bucketed or unproven, is in [signals](../signals.md).

Confirm the kernel still has them after the CLI returns. The daemon keeps the links for the life of the process. A second `shukractl programs` a few seconds later should still say attached. If the process exits, the hooks go with it. This build does not pin into `/sys/fs/bpf`.

## What "attached" is not

Attached means the tracepoint or kprobe is live. It does not mean a guest has been named. `shukractl trace net` is still the QEMU process. Read [attribution](../attribution.md) before you brief anyone with a packet.

Next: [deploy this onto a hypervisor](03-deploy.md) so you are not building by hand.
