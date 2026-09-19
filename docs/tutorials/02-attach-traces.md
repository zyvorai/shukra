# Attach traces

`shukrad` only loads eBPF when three things are true: the binary was built with `-tags shukrabpf`, the host has kernel BTF, and the process can attach tracepoints. The default `make build` skips all of that on purpose, so a Mac and CI do not pretend to be attached.

## What the host needs

- Linux with `/sys/kernel/btf/vmlinux` readable
- `clang`
- `bpftool` (so `make generate` can write `bpf/vmlinux.h`)
- Root, or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`

Check:

```bash
test -r /sys/kernel/btf/vmlinux && echo btf=yes
command -v clang
command -v bpftool
```

KVM trace records are not in vmlinux BTF on Ubuntu 6.8. The `kvm` program uses the tracepoint format directly (`exit_reason` is the first field after the 8-byte common header). Scheduler, block, and TCP programs use the BTF types the kernel does export (`sched_wakeup_template`, `block_rq`, `block_rq_completion`, `tcp_event_sk_skb`). A missing KVM tracepoint detaches only `kvm`. The other three still attach.

## Generate and build

From the repo root, on that Linux host:

```bash
make generate
CGO_ENABLED=0 go build -tags shukrabpf -o bin/shukrad ./cmd/shukrad
CGO_ENABLED=0 go build -o bin/shukractl ./cmd/shukractl
```

`make generate` runs bpf2go into `internal/bpfgen`. Those files are build products. Do not commit `bpf/vmlinux.h`.

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
net       attached    2 hooks
```

Confirm the kernel still has them after the CLI returns. The daemon keeps the links for the life of the process. A second `shukractl programs` a few seconds later should still say attached. If the process exits, the hooks go with it. This build does not pin into `/sys/fs/bpf`.

## What "attached" is not

Attached means the tracepoint or kprobe is live. It does not mean a guest has been named. `shukractl trace net` is still the QEMU process. Read [attribution](../attribution.md) before you brief anyone with a packet.

Next: [deploy this onto a hypervisor](03-deploy.md) so you are not building by hand.
