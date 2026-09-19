# Deploy a hypervisor

Shukra is not a cluster chart. The program has to run on the machine that schedules the vCPUs. `scripts/deploy-remote.sh` follows Netra's operator entry — `HOST USER` or `user@host` — then installs a systemd unit instead of Helm.

## One command

From a checkout, with SSH to the hypervisor:

```bash
./scripts/deploy-remote.sh 10.0.1.5 sus
# or
./scripts/deploy-remote.sh sus@10.0.1.5
```

What it does:

1. Rsyncs the tree to `$HOME/.deployments/shukra` on the host (`SHUKRA_REMOTE_SUBDIR` overrides the directory name).
2. Builds the console with `npm ci` if npm is present.
3. Runs `make generate` when clang and `/sys/kernel/btf/vmlinux` exist, then `go build -tags shukrabpf`. If generate fails, it still builds a detached daemon and says so.
4. Installs `/usr/local/bin/shukrad` and `/usr/local/bin/shukractl`.
5. Installs `configs/detections.example.yaml` as `/etc/shukra/detections.yaml` only if there is none. Your edited rules are kept, and the current sample is always written beside them as `detections.example.yaml`.
6. Writes the API key to `/etc/shukra/env` (root only, `0600`) for the service, and `~/.shukra/env` and `~/.shukra/api-key` for the SSH user. The key is not in the unit file, because `systemctl show` prints a unit's `Environment=` to every local user.
7. Installs `shukra.service` from `deploy/shukra.service` (with `-data-dir /var/lib/shukra` and `ExecReload`), enables it, and restarts it. Detections, isolation requests and the flight recorder now survive that restart.
8. Runs `shukractl status`, `programs`, `vms`, `trace list`, and `GET /api/v1/status`.

The unit listens on `0.0.0.0:30970`. The token defaults to `shukra` unless you export `SHUKRA_API_KEY` before deploying. Set a real token on any host that is not a lab:

```bash
SHUKRA_API_KEY="$(openssl rand -hex 16)" ./scripts/deploy-remote.sh 10.0.1.5 sus
```

Passwordless `sudo` is required for install, the unit file, and `systemctl`.

## What the service is allowed to do

The unit runs as root but with only `CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_RESOURCE`, which is all that attaching tracepoints and kprobes and reading BPF maps needs on Linux 5.8 or newer. On an older kernel the deploy drops those two lines, because `CAP_BPF` does not exist there, and the rest of the hardening stays. The filesystem is read-only to the service except `/var/lib/shukra`, and it cannot gain privileges, load kernel modules, or open sockets other than IP, Unix and netlink. On a 6.8 kernel this was checked by running the real unit: all four programs attached and counted, a write to `/etc` from inside the service failed, and `systemd-analyze security` scored it 4.3 (OK).

## Encrypt the API

The unit listens on plain HTTP, so the bearer key crosses the network in the clear. Turn on TLS by adding arguments to `/etc/shukra/env`:

```bash
echo 'SHUKRA_EXTRA_ARGS=-tls-cert /etc/shukra/tls.crt -tls-key /etc/shukra/tls.key' | sudo tee -a /etc/shukra/env
sudo systemctl restart shukra
```

`systemctl reload shukra` re-reads the certificate as well as the detection rules, so a renewed certificate needs no restart. A bad file on reload is logged and the working certificate stays in use. The floor is TLS 1.2. Point the CLI at a private CA with `SHUKRA_CA_FILE=/path/ca.pem` and `SHUKRA_URL=https://...`. The daemon warns at start when it serves plain HTTP on a non-loopback address.

## A key that can only read

Set `SHUKRA_READONLY_KEY` in `/etc/shukra/env` and give that key to a Prometheus scrape or a dashboard. It can call every `GET`, including `/metrics` and the event stream, and gets `403` on `POST /api/v1/isolate`. It must differ from `SHUKRA_API_KEY`, and the daemon refuses to start otherwise.

## Dry run and re-check

```bash
./scripts/deploy-remote.sh 10.0.1.5 sus --dry-run
./scripts/deploy-remote.sh 10.0.1.5 sus --verify-only
```

`--verify-only` does not rsync. It checks the unit and the CLI against whatever is already installed.

## What good looks like

`systemctl is-active shukra` prints `active`.

`shukractl programs` prints four lines of `attached` when BTF and clang were available. If generate failed, they are `detached` and the deploy log said `make generate failed`. Detached is a successful install of the control plane. It is not a successful trace.

`shukractl vms` lists `qemu-system-*` processes. `runtime=libvirt` or `runtime=kubevirt` is a label from the command line, not a guest agent. `taps=-` means no `ifname=` was parsed. That tap name is recorded for a later slice. It is not traced.

From your laptop, if the port is reachable:

```bash
curl -sf -H "Authorization: Bearer $SHUKRA_API_KEY" \
  http://10.0.1.5:30970/api/v1/status
```

`programsAttached` should match what the CLI printed. `guest` attribution is not a field you should expect to flip to true.

## After a reboot

The unit is `WantedBy=multi-user.target` and `Restart=on-failure`. Hooks are not pinned. They come back when `shukrad` starts, not because something left them in `/sys/fs/bpf`.

Next: [use the CLI](04-shukractl.md) against that URL.
