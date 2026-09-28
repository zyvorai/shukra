# Getting started

Back to the [README](../README.md).

## Quick start

Go 1.27+ and Node 22 for the console.

```bash
make build
make web
./bin/shukrad -listen 127.0.0.1:30970 -web web/dist
./bin/shukractl status
```

If `SHUKRA_API_KEY` is unset, the daemon uses the dev token `shukra` and says so on stderr. Open `http://127.0.0.1:30970` and sign in with that token.

On a Mac, or any host without BTF, programs stay detached. VM discovery from `/proc` still works. To attach traces you need Linux, clang, bpftool and kernel BTF: see [Attach traces](tutorials/02-attach-traces.md). To look at the console with no daemon at all, use fixture mode (see [Development](build-and-test.md)); it is not live data.

## Deploy a hypervisor

Shukra is a systemd unit on the hypervisor, not a Helm chart. eBPF has to run where the VMs run.

```bash
./scripts/deploy-remote.sh 10.0.1.5 sus
```

That rsyncs the tree, builds the console and the CO-RE objects on the host, installs `shukrad` and `shukractl` to `/usr/local/bin`, and starts `shukra.service` on `127.0.0.1:30970`. The script checks the daemon on that address. A packaged install generates a random `SHUKRA_API_KEY` when the host has none; a binary you start yourself with the variable unset uses the dev token `shukra`. For a host without a compiler, `make dist` builds a tarball and a `.deb`, and `--prebuilt` deploys one. Keys and extra daemon flags go in `/etc/shukra/env` (`SHUKRA_API_KEY`, `SHUKRA_READONLY_KEY`, `SHUKRA_WEBHOOK_SECRET`, `SHUKRA_EXTRA_ARGS`). The unit reads its rules from `/etc/shukra/detections.yaml` and keeps state in `/var/lib/shukra`. Remote access needs TLS in front of loopback, or an explicit `-listen` plus `-tls-cert`/`-tls-key` or `-allow-insecure-http`. Full walkthrough: [Deploy a hypervisor](tutorials/03-deploy.md).

## Operator loop

```bash
shukractl status                            # the one screen to trust first
shukractl doctor                            # what needs attention, worst first, each with a fix
shukractl programs                          # which programs are attached, and why one is not
shukractl vms                               # QEMU and FluxVM VMs found on the host
shukractl explain osboxes-debian            # the last minute; --window 5m or lifetime to change it
shukractl explain osboxes-debian --at -3h   # a past time, from stored 5-minute snapshots
shukractl incident osboxes-debian --at -3h --out bundle.json   # verdict, detections, events, isolations
shukractl trace kvm --vm osboxes-debian     # also sched, block, net, tap, drops, contention
shukractl trace tap --vm osboxes-debian     # the guest's traffic and what became of its connections
shukractl trace drops --vm osboxes-debian   # what the kernel dropped on its tap, and whether it was Shukra
shukractl trace contention                  # which VM took whose CPU
shukractl advise                            # over-provisioned or starved VMs, with the numbers
shukractl baseline                          # what each VM has learned as normal; --items for one VM's list
shukractl recorder osboxes-debian --window 60s
shukractl watch --json                      # stream events, resuming from the last one seen
shukractl security osboxes-debian           # rule hits for one VM
shukractl actions                           # proposals waiting for a person; approve <id> or reject <id>
shukractl policy learn osboxes-debian       # what its baseline says it may connect to
shukractl policy apply osboxes-debian --mode audit --from-baseline
shukractl isolate osboxes-debian            # needs -isolate-allow; prints whether it was applied
shukractl release osboxes-debian
shukractl rules check detections.yaml       # validate a rules file offline
```

`~/.shukra/env` is loaded when a variable is not already set. `SHUKRA_URL` defaults to `http://127.0.0.1:30970`. All 21 commands, flags and exit codes: [shukractl](shukractl.md), or `shukractl help`.

```text
shukractl  →  HTTP  →  shukrad  →  tracepoints / kprobes / TCX on each VM tap
                              ↘  /proc QEMU scan
```

The CLI never attaches a program. The tap program pins its links and maps under `/sys/fs/bpf/shukra/tap`, so an isolation outlives the daemon: see [Guest traffic and isolation](tap.md).
