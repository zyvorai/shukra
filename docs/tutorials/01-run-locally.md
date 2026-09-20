# Run it locally

You can build and browse Shukra on a laptop. Programs will report detached. That is correct. The daemon still scans `/proc` for `qemu-system-*` and, if FluxVM's store is readable, for its VMMs, and serves the API. It does not fill in counters it did not collect.

## Build

Go 1.25 or newer. Node 22 if you want the console bundle.

```bash
make build
make web
```

`make build` writes `bin/shukrad` and `bin/shukractl`. `make web` runs the console tests and writes `web/dist`.

## Start the daemon

```bash
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist
```

If `SHUKRA_API_KEY` is empty, the log line is the token: `shukra`. Set your own before you listen on anything but loopback.

```bash
export SHUKRA_API_KEY="$(openssl rand -hex 16)"
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist -watchlist configs/detections.example.yaml
```

Flags:

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:30970` | API and console |
| `-proc` | `/proc` | Where QEMU is discovered |
| `-watchlist` | empty | [Detection rules](06-watchlist.md) YAML. No file means only the built-in unexpected-exec check |
| `-web` | `web/dist` | Console bundle. Missing directory means API only |
| `-data-dir` | empty | Keep detections, isolations and the recorder across restarts |
| `-webhook-url`, `-syslog`, `-alert-file` | off | [Alert sinks](07-alert-sinks.md) |
| `-no-auth` | off | Serve without a bearer key. Otherwise `SHUKRA_API_KEY`, or the dev token with a warning |
| `-tls-cert`, `-tls-key` | off | Serve HTTPS. `SIGHUP` reloads the certificate |
| `-isolate-allow` | empty | Comma-separated CIDRs an isolated VM can still reach. Without it, isolate is refused. See [guest traffic](../tap.md) |
| `-dns-events` | on | Record the names a guest looks up (`guest_dns` events). `-dns-events=false` makes the tap program not read DNS at all. See [DNS names](../tap.md#dns-names) |
| `-detach-all` | off | Remove every pinned tap program and its isolation, then exit. Works while the daemon is stopped |
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

`programs` should list `kvm`, `sched`, `block`, `net`, `drops` and `tap`, each `detached` with the reason beside it and no invented numbers. `vms` is empty unless a `qemu-system` process, or a FluxVM VMM listed in `vms.json`, is actually running on this machine.

The same token signs you into the console at `http://127.0.0.1:30970`.

## Console without a daemon

Useful for layout work.

```bash
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

Next: [attach the traces](02-attach-traces.md) on Linux, or [deploy](03-deploy.md) straight to a hypervisor.
