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
3. Runs `make generate` when clang and `/sys/kernel/btf/vmlinux` exist, then `go build -tags shukrabpf`. If the host has both and the objects still do not build (a missing `llvm-strip` or `bpftool` counts), the script stops with `ERROR: clang and kernel BTF are present but the CO-RE objects did not build`, installs nothing and leaves the running service alone. `SHUKRA_ALLOW_DETACHED=1` installs a detached daemon anyway. On a host with no clang or no BTF it builds a detached daemon, and says `programs will report detached`.
4. Installs `/usr/local/bin/shukrad` and `/usr/local/bin/shukractl`.
5. Installs `configs/detections.example.yaml` as `/etc/shukra/detections.yaml` only if there is none. Your edited rules are kept, and the current sample is always written beside them as `detections.example.yaml`.
6. Writes the API key to `/etc/shukra/env` (root only, `0600`) for the service, and `~/.shukra/env` and `~/.shukra/api-key` for the SSH user. The key is not in the unit file, because `systemctl show` prints a unit's `Environment=` to every local user.
7. Installs `shukra.service` from `deploy/shukra.service` (with `-data-dir /var/lib/shukra` and `ExecReload`), enables it, and restarts it. Detections, isolation requests and the flight recorder now survive that restart, and the daemon stores a coarse snapshot every 5 minutes so that a past time can be explained (`snapshots.jsonl`, about a day at ten VMs; see [after the fact](09-after-the-fact.md)).
8. Waits for the daemon to answer (`shukractl status --wait`, since it takes a couple of seconds to load its programs), then runs `status`, `programs`, `vms`, `trace list`, `doctor` and `GET /api/v1/status`. `doctor` is informational here: a fresh deploy on a lab host may list the dev key if you started the binary yourself without `SHUKRA_API_KEY`, and the script says so without failing. The installed unit does not use the dev key: `deploy/install.sh` writes a random one when the host has none.

The unit listens on `127.0.0.1:30970`. A binary you start by hand with `SHUKRA_API_KEY` unset uses the dev token `shukra` and says so. A packaged install and `deploy-remote.sh` generate a random key instead, and keep the key already on the host unless you export `SHUKRA_API_KEY`. Set one explicitly when you want a known value:

```bash
SHUKRA_API_KEY="$(openssl rand -hex 16)" ./scripts/deploy-remote.sh 10.0.1.5 sus
```

Passwordless `sudo` is required for install, the unit file, and `systemctl`.

You should see the script's numbered progress, then the same board you get from the CLI, ending with:

```text
SHUKRA_URL=http://127.0.0.1:30970
Shukra ready
```

That URL is on the hypervisor, not your laptop. The API is not reachable from the network until you put TLS in front of it or explicitly open plain HTTP (below).

## What the service is allowed to do

The unit runs as root but with only six capabilities, each there for a reason that was checked by removing it:

| Capability | Why |
|---|---|
| `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` | load programs, attach tracepoints and kprobes, read maps |
| `CAP_NET_ADMIN` | load and attach the TCX tap program. Without it the tap program fails to load with `operation not permitted` |
| `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH` | read a VM's tap names from the tun file descriptors of a QEMU that runs as another user. libvirt passes taps as fds, so the names are not on the command line. Without either, those VMs have no known tap |

`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` are broad. They are needed only to read `/proc/<pid>/fd` and `fdinfo` of processes owned by another user, and the daemon never calls `ptrace`. If you run no libvirt VMs and want them off, remove those two from both capability lines in the unit and QEMU processes started with `ifname=` on their command line will still be found. On a kernel older than 5.8 the deploy drops the capability lines entirely, because `CAP_BPF` does not exist there, and the rest of the hardening stays. The filesystem is read-only to the service except `/var/lib/shukra`, and it cannot gain privileges, load kernel modules, or open sockets other than IP, Unix and netlink. On a 6.8 kernel this was checked by running the real unit: all programs attached and counted, a libvirt-style VM's tap was found and instrumented, a write to `/etc` from inside the service failed, and `systemd-analyze security` scored the earlier three-capability set 4.3 (OK).

## Encrypt the API

The unit listens on `127.0.0.1:30970` over plain HTTP. That is safe for `shukractl` on the hypervisor. It is not reachable from another machine.

To open it remotely, terminate TLS on the hypervisor and proxy to loopback. Do not put the bearer key on the network in the clear. The daemon refuses to start if `-listen` is not a loopback address, TLS is unset, and `-allow-insecure-http` is unset. `-no-auth` on a non-loopback address is refused even with that flag.

Caddy:

```text
shukra.example.com {
    reverse_proxy 127.0.0.1:30970
}
```

NGINX:

```text
server {
    listen 443 ssl;
    server_name shukra.example.com;
    ssl_certificate     /etc/shukra/tls.crt;
    ssl_certificate_key /etc/shukra/tls.key;
    location / {
        proxy_pass http://127.0.0.1:30970;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;
    }
}
```

HAProxy:

```text
frontend shukra
    bind :443 ssl crt /etc/shukra/tls.pem
    default_backend shukrad
backend shukrad
    server local 127.0.0.1:30970
```

The event stream is a long-lived response, so the proxy must not buffer it (`proxy_buffering off` in NGINX; HAProxy does not buffer by default).

The daemon can also serve TLS itself. There must be **one** `SHUKRA_EXTRA_ARGS=` line in `/etc/shukra/env`. The service reads it as a list of assignments and the last one wins, so a second `tee -a` for another flag would silently drop the first.

```bash
echo 'SHUKRA_EXTRA_ARGS=-listen 0.0.0.0:30970 -tls-cert /etc/shukra/tls.crt -tls-key /etc/shukra/tls.key' | sudo tee -a /etc/shukra/env
sudo systemctl restart shukra
```

`systemctl reload shukra` re-reads the certificate as well as the detection rules, so a renewed certificate needs no restart. A bad file on reload is logged and the working certificate stays in use. The floor is TLS 1.2. Point the CLI at a private CA with `SHUKRA_CA_FILE=/path/ca.pem` and `SHUKRA_URL=https://shukra.example.com`. `shukractl doctor` warns when it sees plain HTTP on a non-loopback address, which only happens if you passed `-allow-insecure-http`.

A lab that must keep the old plain-HTTP bind sets both flags, and accepts that the key is visible on the network:

```text
SHUKRA_EXTRA_ARGS=-listen 0.0.0.0:30970 -allow-insecure-http
```

## Other daemon options

Anything `shukrad` takes can be added the same way, in the one `SHUKRA_EXTRA_ARGS` line in `/etc/shukra/env`, then `sudo systemctl restart shukra`. A later flag wins over one in the unit. With several, the line looks like this:

```text
SHUKRA_EXTRA_ARGS=-tls-cert /etc/shukra/tls.crt -tls-key /etc/shukra/tls.key -isolate-allow 10.0.0.0/24 -dns-events=false
```

The ones a fresh deploy usually needs:

| Flag | Why |
|---|---|
| `-isolate-allow 10.0.0.0/24` | Enables isolate, and [enforcing an egress policy](10-egress-policy.md), which are refused without a management allow list. It also means anyone who holds the admin key can cut a VM off, so first give the host a real key and TLS (or `-listen 127.0.0.1:30970`): `shukractl doctor` fails a host that still has the dev key `shukra` on a public address or plain HTTP, and this flag should not go on one |
| `-dns-events=false` | Do not record the names guests look up. The tap program then does not read DNS at all |
| `-vmm-tripwires=false` | Do not load the program that watches QEMU processes for the files they open and the calls they make ([tutorial 11](11-vmm-tripwires.md)). It runs on every open on the host, about 200 ns each, plus a hook on every process creation and exit |
| `-tls-events=false` | Do not record the server names in guests' TLS hellos. The tap program then reads no TCP payload at all |
| `-webhook-url`, `-syslog`, `-alert-file` | Where detections go. See [alert sinks](07-alert-sinks.md) |
| `-listen 0.0.0.0:30970` | Bind an address other than loopback. Plain HTTP then also needs `-allow-insecure-http`, or `-tls-cert` and `-tls-key` |
| `-allow-insecure-http` | Permit plain HTTP on a non-loopback address. The bearer key crosses the network in the clear |

`shukractl doctor` names what is missing, with a fix for each: [doctor](../doctor.md).

## A key that can only read

Set `SHUKRA_READONLY_KEY` in `/etc/shukra/env` and give that key to a Prometheus scrape or a dashboard. It can call every `GET`, including `/metrics` and the event stream, and gets `403` (`this key is read-only`) on every `POST`: isolate, release, approve and reject, `policy apply`, confirm and remove, and `baseline --forget`. It must differ from `SHUKRA_API_KEY`, and the daemon refuses to start otherwise.

## Deploy without a compiler on the host

`shukrad` carries its eBPF programs compiled in, so a host that only runs it needs kernel BTF (`/sys/kernel/btf/vmlinux`), not go, clang or bpftool. Build on a machine of the same architecture and ship the result:

```bash
make dist                      # dist/shukra-<version>-linux-<arch>.tar.gz and a .deb
./scripts/deploy-remote.sh 10.0.1.5 sus --prebuilt dist/shukra-v1.2.3-linux-amd64.tar.gz
```

The tarball holds `bin/`, `deploy/`, `configs/` and the console, and `deploy/install.sh` installs it. That is the same routine the source deploy and the `.deb` run, so all three lay down the same files. `make dist` needs Linux with clang, `llvm-strip`, `bpftool` and BTF, because `bpf/vmlinux.h` comes from the build machine's kernel. Build each architecture on that architecture. CO-RE then lets the binary run on other kernels of the same architecture.

On Debian or Ubuntu the `.deb` does the whole install:

```bash
sudo dpkg -i shukra_1.2.3_amd64.deb
sudo grep SHUKRA_API_KEY /etc/shukra/env      # a random key was generated on first install
```

It installs `/usr/bin/shukrad` and `/usr/bin/shukractl`, the unit, and the sample rules, and starts the service. Upgrading keeps your rules and key, `dpkg -r` keeps `/etc/shukra`, and `dpkg -P` removes it and `/var/lib/shukra`. The unit listens on `127.0.0.1:30970`. To reach it from another machine, terminate TLS in a proxy (above) or set `-listen` together with `-tls-cert`/`-tls-key` or `-allow-insecure-http` in the one `SHUKRA_EXTRA_ARGS` line. No `.rpm` is built yet.

Pushing a tag such as `v1.2.3` runs `.github/workflows/release.yml`, which builds both packages for amd64 and arm64 and attaches them, with checksums, to a GitHub release. That workflow has not run yet, so treat its first run as a test.

`shukrad -version` and `shukractl version` print the stamped version. A source deploy builds on the host and reports the git describe, or `0.1.0` when the host has no `.git`.

## Upgrading a host that listened on every interface

A unit from before this default bound `0.0.0.0:30970` over plain HTTP. Replacing the unit binds `127.0.0.1:30970` and does not keep the old address. `curl` from a laptop to the hypervisor's public address stops working until you do one of these:

- Put Caddy, NGINX or HAProxy TLS in front of `127.0.0.1:30970` (above). This is the supported remote setup.
- Or, only for a lab, set `SHUKRA_EXTRA_ARGS=-listen 0.0.0.0:30970 -allow-insecure-http` in `/etc/shukra/env` and restart. Both flags are required. The daemon will not start with only `-listen 0.0.0.0:30970`.

`/etc/shukra` and `/var/lib/shukra` are kept across the package upgrade. Roll back by installing the previous `.deb` (`dpkg -i`) and restarting. That restores the old unit if it shipped inside that package. The key and data directory stay.

## Upgrading a host deployed by an older script

The first deploy with this script moves the API key out of the unit file into `/etc/shukra/env` and keeps the same key, so consoles and scripts that use it keep working. It keeps an edited `/etc/shukra/detections.yaml`. If you export `SHUKRA_API_KEY` the key is replaced; if you do not, the current one is kept, and a host with none gets a random one, which is printed once.

## Dry run and re-check

```bash
./scripts/deploy-remote.sh 10.0.1.5 sus --dry-run
./scripts/deploy-remote.sh 10.0.1.5 sus --verify-only
```

`--verify-only` does not rsync. It checks the unit and the CLI against whatever is already installed.

## What good looks like

`systemctl is-active shukra` prints `active`.

`shukractl programs` prints seven lines: `kvm`, `sched`, `block`, `net`, `vmm` and `drops` `attached` with a hook count, and `tap` `attached` with how many VM taps it is on (or `detached: no VM tap interfaces to attach to yet` on a host with no VMs) when BTF and clang were available, and `shukractl status` says `programs    7/7 attached`. On a host with no clang or BTF (or with `SHUKRA_ALLOW_DETACHED=1` after a failed build) they are `detached`, and the deploy log said `programs will report detached` or `CO-RE objects were not generated`. Detached is a successful install of the control plane.

`shukractl vms` lists `qemu-system-*` processes and FluxVM VMMs (`cloud-hypervisor`, `firecracker`, `fluxvm-hypervisor`, and QEMU guests FluxVM launched). `runtime=libvirt` or `runtime=kubevirt` is a label from the QEMU command line, not a guest agent. `runtime=fluxvm` means the name, UUID and tap came from FluxVM's `vms.json`. `taps=` is the interface Shukra will attach to: `ifname=` or a libvirt tun fd for a plain QEMU guest, and for FluxVM the host veth `vh<8hex>` when the guest's tap is in a per-VM netns, or `tap_name` when it is already on the host. A VM with `taps=-` is on user-mode networking or its interface could not be mapped, and `shukractl doctor` says which, so its guest traffic is not seen and it cannot be isolated. The mapping is in [FluxVM](../tap.md#fluxvm).

From your laptop, only after TLS or an explicit insecure bind:

```bash
curl -sf -H "Authorization: Bearer $SHUKRA_API_KEY" \
  https://shukra.example.com/api/v1/status
```

`programsAttached` should match what the CLI printed. `guest` attribution is not a field you should expect to flip to true.

## After a reboot

The unit is `WantedBy=multi-user.target` and `Restart=on-failure`. The kernel programs come back when `shukrad` starts. The tap program's links and maps are pinned under `/sys/fs/bpf/shukra/tap`, so an isolated VM (or one under an enforcing egress policy) stays that way while the daemon is down and the restarted daemon adopts what is there: see [guest traffic and isolation](../tap.md). A graceful stop detaches every tap that is not isolated and has no enforcing egress policy, so nothing of Shukra is left on an ordinary VM's interface.

If you develop Shukra, this is also how a BPF change is verified: deploy to a real hypervisor and test there ([testing](../testing.md)).

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `Permission denied (publickey)`, or the script hangs at the first step | The script needs SSH to `HOST` as `USER`, and passwordless `sudo` there. Try `ssh USER@HOST sudo -n true` |
> | `ERROR: clang and kernel BTF are present but the CO-RE objects did not build` | Nothing was installed and the running service was not touched. Install the missing tool (`llvm-strip`, `bpftool`) or fix the build: [attach traces](02-attach-traces.md). To install a detached daemon anyway, `SHUKRA_ALLOW_DETACHED=1 ./scripts/deploy-remote.sh ...` |
> | `programs will report detached` in the log | The host has no `clang` or no BTF. The control plane installed and every program is `detached` |
> | `shukractl status --wait` times out | `sudo journalctl -u shukra -n 50`. A bad `SHUKRA_EXTRA_ARGS` flag or an unreadable certificate stops the daemon at start |
> | `systemctl is-active shukra` prints `failed` | Same journal. A second `SHUKRA_EXTRA_ARGS=` line in `/etc/shukra/env` replaces the first: keep one |
> | `curl` from your laptop cannot connect | The unit binds `127.0.0.1:30970`. Use SSH to the host, or put TLS in front of loopback. A firewall is only relevant after you have opened a non-loopback listen |
> | the daemon exits at start with `refusing plain HTTP` | `-listen` is not loopback and there is no TLS. Add `-tls-cert` and `-tls-key`, or `-allow-insecure-http` if you accept a cleartext key |
> | `401` from `curl` | The key is the one in `/etc/shukra/env`: `sudo grep SHUKRA_API_KEY /etc/shukra/env`. A fresh install generated a random key. The dev token `shukra` is only what a binary uses when `SHUKRA_API_KEY` is unset |
> | `doctor` lists the dev key | You started `shukrad` without `SHUKRA_API_KEY`. A packaged install does not do that. Set `SHUKRA_API_KEY` in `/etc/shukra/env` |
> | Every program is `detached` | Read the detail beside it. A missing BPF build says `CO-RE objects are not linked in this binary` |

Next: [use the CLI](04-shukractl.md) against that URL.
