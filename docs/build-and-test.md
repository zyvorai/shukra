# Build, test and CI

Back to the [README](../README.md).

```bash
make test          # go test ./...
make web           # npm ci, unit tests, production build
make generate      # no-op without clang and /sys/kernel/btf/vmlinux
make test-bpf      # the tagged (shukrabpf) build and its tests (Linux, after make generate)
make test-kernel   # load the programs into this kernel and check the counters (root, Linux)
make test-tap      # guest traffic, isolation, drops, handshakes, egress policy and the VMM tripwires in a network namespace (root, Linux 6.6+)
make test-live-guest  # real KVM guests booted by fluxvm, seen by a running daemon (a hypervisor with fluxvm)
make dist          # release tarball and .deb for this architecture (Linux)
```

Default `go build` does not link CO-RE objects, so CI and macOS stay green. The Linux tag is `shukrabpf`. A missing KVM tracepoint detaches only the `kvm` program. Fixtures for tests live under `testdata/`.

| Where it is safe | Test |
|---|---|
| Anywhere, including a Mac | `make test`, `make web` |
| A Linux host, including a production hypervisor: the programs are private copies with their own maps | `make test-kernel`, `scripts/test-tap-progrun.sh` (the tap program's egress policy packet by packet), `scripts/bench-tap.sh` (per-packet cost), `make test-live-guest` |
| **Never a hypervisor already running Shukra** | `make test-tap` |

`make test-tap` shares the pin directory with the daemon and its cleanup removes every pinned tap link. [Testing](testing.md) says what each test proves and how a BPF change is verified without a local Linux VM (write it, type-check the tagged build, deploy to a real host, let CI run the rig). [Development](development.md) is the guide to the code.

## Continuous integration

| Workflow | Runs | What it proves |
|---|---|---|
| `CI` | every push and pull request | Go and console tests; race detector; vet; staticcheck; govulncheck; short fuzz; npm audit; coverage artifact; the tagged build; the programs loaded into the runner's kernel; the tap rig; the installer; the same Go and console tests on arm64 |
| `Live guest (fluxvm)` | weekly, by hand, and on changes to the tap code, the VMM tripwire code, identity code or the test | Two real KVM guests booted by fluxvm on a runner with `/dev/kvm`: the taps are attached as hot-plugs, guest events are attributed, one guest reaches the other, packet counts equal the kernel's, DNS and TLS names arrive as asked, an egress policy in audit mode marks exactly what is outside its list, a real QEMU is on the kernel's watched list, raises no tripwire detection while it runs, and raises a critical `vmm-sensitive-open` when asked over QMP to open `/etc/shadow`, and the taps come off when the VMs are deleted. It fails, rather than skips, on a runner with no KVM |
| `Release` | a `v*` tag | The tarball, `.deb`, container image and checksums for each architecture, a CycloneDX SBOM, and cosign signatures when `COSIGN_PRIVATE_KEY` is set |

## Fixture mode

```bash
cd web && VITE_FIXTURE=1 npm run dev
```

Fixture mode is a local console with no daemon. It is not live data.

## Brochure and social image

Both are generated, so they can be regenerated when the product changes.

```bash
python3 docs/sales/brochure/build.py --check   # the brochure PDF; fails if a page overflows
docs/sales/brochure/capture.sh                 # re-shoot the console pages from fixture mode
docs/social/build-social-card.sh               # docs/shukra-social.png and web/public/og.png, byte-identical
```

The brochure and the social card need Google Chrome (the card also needs macOS `sips`). Every number in the brochure has a source in [its claims table](sales/brochure/README.md).
