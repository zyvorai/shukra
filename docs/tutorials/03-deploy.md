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
5. Copies `configs/detections.example.yaml` to `/etc/shukra/detections.yaml`.
6. Writes `~/.shukra/env` and `~/.shukra/api-key` for the SSH user.
7. Installs `shukra.service` (with `-data-dir /var/lib/shukra` and `ExecReload`), enables it, and restarts it. Detections, isolation requests and the flight recorder now survive that restart.
8. Runs `shukractl status`, `programs`, `vms`, `trace list`, and `GET /api/v1/status`.

The unit listens on `0.0.0.0:30970`. The token defaults to `shukra` unless you export `SHUKRA_API_KEY` before deploying. Set a real token on any host that is not a lab:

```bash
SHUKRA_API_KEY="$(openssl rand -hex 16)" ./scripts/deploy-remote.sh 10.0.1.5 sus
```

Passwordless `sudo` is required for install, the unit file, and `systemctl`.

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
