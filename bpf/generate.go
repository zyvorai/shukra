package bpf

// Generate CO-RE objects on Linux. Skipped by `make generate` when clang or BTF is missing.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem kvm -target amd64 -cc clang Kvm kvm.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem sched -target amd64 -cc clang Sched sched.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem block -target amd64 -cc clang Block block.bpf.c -- -I. -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package bpfgen -output-dir ../internal/bpfgen -output-stem net -target amd64 -cc clang Net net.bpf.c -- -I. -O2 -g
