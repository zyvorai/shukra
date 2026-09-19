.PHONY: deps generate build test install web

PREFIX ?= /usr/local

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
	go build -o bin/shukrad ./cmd/shukrad
	go build -o bin/shukractl ./cmd/shukractl

test:
	go test ./...

web:
	npm --prefix web ci
	npm --prefix web test
	npm --prefix web run build

install: build
	install -d $(PREFIX)/bin
	install -m 755 bin/shukractl $(PREFIX)/bin/shukractl
	install -m 755 bin/shukrad $(PREFIX)/bin/shukrad
