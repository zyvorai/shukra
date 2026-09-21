# Run it locally

You can build and browse Shukra on a laptop. Programs will report detached. That is correct. The daemon still scans `/proc` for `qemu-system-*` and, if FluxVM's store is readable, for its VMMs, and serves the API. It does not fill in counters it did not collect.

## Build

Go 1.27 or newer. Node 22 if you want the console bundle.

```bash
make build
make web
```

`make build` writes `bin/shukrad` and `bin/shukractl`, stamped with `git describe`. `make web` installs the console's packages, runs its tests and writes `web/dist`.

You should see:

```bash
./bin/shukractl version
```

```text
shukractl v0.1.0-12-gabc1234
```

(Your version is your checkout's `git describe`, or `0.1.0` when there is no `.git`.) `ls web/dist/index.html` exists once `make web` has finished.

## Start the daemon

```bash
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist
```

If `SHUKRA_API_KEY` is empty, the log line is the token: `shukra`. Set your own before you listen on anything but loopback.

```bash
export SHUKRA_API_KEY="$(openssl rand -hex 16)"
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist -watchlist configs/detections.example.yaml
```

You should see the daemon say what it is and where:

```text
2026/09/20 09:00:00 shukra v0.1.0-12-gabc1234 listening on http://127.0.0.1:30970 (eBPF-powered runtime intelligence and security for KVM)
```

With no key set there is a `WARNING: SHUKRA_API_KEY unset; using the well-known dev token "shukra"` line first. A daemon that listens on anything but loopback over plain HTTP also warns that the key crosses the network in the clear.

Flags:

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:30970` | API and console |
| `-proc` | `/proc` | Where QEMU is discovered |
| `-watchlist` | empty | [Detection rules](06-watchlist.md) YAML. No file means only the built-in unexpected-exec check and the built-in [VMM tripwire](11-vmm-tripwires.md) paths |
| `-web` | `web/dist` | Console bundle. Missing directory means API only |
| `-data-dir` | empty | Keep detections, isolations, the recorder, learned baselines and egress policies across restarts, and a coarse snapshot every 5 minutes that `explain --at` and `incident` read. Enforcing an [egress policy](10-egress-policy.md) needs it |
| `-webhook-url`, `-syslog`, `-alert-file` | off | [Alert sinks](07-alert-sinks.md) |
| `-no-auth` | off | Serve without a bearer key. Otherwise `SHUKRA_API_KEY`, or the dev token with a warning |
| `-tls-cert`, `-tls-key` | off | Serve HTTPS. `SIGHUP` reloads the certificate |
| `-isolate-allow` | empty | Comma-separated CIDRs an isolated VM can still reach, and the floor an egress policy never judges. Without it, isolate and enforcing are refused. It also lets whoever holds the admin key cut a VM off, so set a real key and TLS first. See [guest traffic](../tap.md) |
| `-vmm-tripwires` | on | Watch QEMU processes, and what they start, for the files they open and the calls a VMM never makes (`vmm_file_open`, `vmm_syscall`, and detections). `-vmm-tripwires=false` does not load the program. See [VMM tripwires](../vmm-tripwires.md) |
| `-tls-events` | on | Record the server name in a guest's TLS ClientHello (`guest_tls` events). `-tls-events=false` makes the tap program read no TCP payload at all. See [TLS server names](../tap.md#tls-server-names) |
| `-dns-events` | on | Record the names a guest looks up (`guest_dns` events). `-dns-events=false` makes the tap program not read DNS at all. See [DNS names](../tap.md#dns-names) |
| `-detach-all` | off | Remove every pinned tap program and its isolation and egress policy, then exit. Works while the daemon is stopped |
| `-version` | off | Print the version and exit |

## Ask the CLI

In another terminal:

```bash
export SHUKRA_URL=http://127.0.0.1:30970
export SHUKRA_API_KEY=shukra   # or the token you set
./bin/shukractl status
./bin/shukractl programs
./bin/shukractl vms
```

`status` reads like this on a laptop:

```text
SHUKRA
  product     shukra
  version     v0.1.0-12-gabc1234
  tagline     eBPF-powered runtime intelligence and security for KVM
  mode        observe
  vms         0
  programs    0/7 attached
  detections  0
  observe: host traces only, guest tap attribution not attached
```

`programs` should list `kvm`, `sched`, `block`, `net`, `vmm`, `drops` and `tap` (seven), each `detached` with the reason beside it and no invented numbers:

```text
PROGRAMS
  kvm       detached    CO-RE objects are not linked in this binary. On Linux: make generate && go build -tags shukrabpf. No counters were invented.
  ...
  tap       detached    CO-RE objects are not linked in this binary. ...
```

`vms` is empty unless a `qemu-system` process, or a FluxVM VMM listed in `vms.json`, is actually running on this machine:

```text
VMS
  none — no qemu-system or FluxVM VMM process in the proc scan
```

The same token signs you into the console at `http://127.0.0.1:30970`. There is no username. The console keeps the token in memory only, so a reload asks again.

## Console without a daemon

Useful for layout work.

```bash
npm --prefix web ci          # once
cd web
VITE_FIXTURE=1 npm run dev
```

Open `http://127.0.0.1:5173` and sign in with `shukra`. The pages are a fixture. Do not treat them as a live hypervisor.

## Tests

```bash
make test
npm --prefix web test
```

The Go tests run anywhere. How the kernel-level tests work, and which of them must never run on a live hypervisor, is in [testing](../testing.md).

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `make: ... go: command not found`, or an error about the Go version | Go 1.27 or newer, on `PATH` |
> | `make web` fails at `npm ci` | Node 22 and `npm` on `PATH`. The daemon and CLI build without them; only the console needs them |
> | `bind: address already in use` | Something is on `30970`. Pick another `-listen` and set `SHUKRA_URL` to match, or find it with `lsof -i :30970` |
> | `shukractl` says `{"error":"unauthorized"}` | `SHUKRA_API_KEY` must be the daemon's key. With none set on either side, use `shukra` |
> | `shukractl` says `dial tcp ...: connect: connection refused` | The daemon is not running, or `SHUKRA_URL` points somewhere else |
> | The browser shows JSON or nothing at `/` | The daemon has no console: `web/dist` is missing. Run `make web`, or pass `-web` the right directory |
> | Every program says `detached` | That is the honest result of a build without BPF. Nothing is wrong. See [attach traces](02-attach-traces.md) |

Next: [attach the traces](02-attach-traces.md) on Linux, or [deploy](03-deploy.md) straight to a hypervisor.
