.PHONY: deps generate build test install web dist

PREFIX ?= /usr/local

# Stamped into both binaries. A tag gives v1.2.3; otherwise the short commit.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)
LDFLAGS := -X github.com/zyvorai/shukra/internal/version.Version=$(VERSION)

deps:
	go mod download

generate:
	@set -eu; \
	if ! command -v clang >/dev/null 2>&1; then echo "clang not found; skipping generate"; exit 0; fi; \
	if ! command -v llvm-strip >/dev/null 2>&1; then echo "llvm-strip not found; skipping generate"; exit 0; fi; \
	if [ ! -r /sys/kernel/btf/vmlinux ]; then echo "no kernel BTF; skipping generate"; exit 0; fi; \
	if ! command -v bpftool >/dev/null 2>&1; then echo "bpftool not found; skipping generate"; exit 0; fi; \
	if ! bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; then \
		echo "bpftool cannot dump this kernel's BTF; skipping generate"; \
		rm -f bpf/vmlinux.h; \
		exit 0; \
	fi; \
	go generate ./bpf/

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/shukrad ./cmd/shukrad
	go build -ldflags "$(LDFLAGS)" -o bin/shukractl ./cmd/shukractl

# A release tarball and a .deb for this machine's architecture, in dist/. Needs
# Linux with clang, bpftool and kernel BTF, since the CO-RE objects are compiled
# in and the result then needs only kernel BTF to run.
dist:
	VERSION=$(VERSION) ./scripts/package.sh

test:
	go test ./...

# Compiles the loader. Requires `make generate` on Linux; on Darwin the linux
# build tag keeps these files out, so this target is for CI and a hypervisor.
test-bpf:
	go test -count=1 -tags shukrabpf ./...

web:
	npm --prefix web ci
	npm --prefix web test
	npm --prefix web run build

install: build
	install -d $(PREFIX)/bin
	install -m 755 bin/shukractl $(PREFIX)/bin/shukractl
	install -m 755 bin/shukrad $(PREFIX)/bin/shukrad
