package bpf

// Generate CO-RE objects on Linux for the architecture you run this on: go generate
// sets $GOARCH, and vmlinux.h is dumped from the running kernel's BTF, which is
// architecture specific. Skipped by `make generate` when clang or BTF is missing.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem kvm -target $GOARCH -cc clang Kvm kvm.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem sched -target $GOARCH -cc clang Sched sched.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem block -target $GOARCH -cc clang Block block.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem net -target $GOARCH -cc clang Net net.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem tap -target $GOARCH -cc clang Tap tap.bpf.c -- -I. -O2 -g
