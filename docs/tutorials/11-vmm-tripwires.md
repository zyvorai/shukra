# Watching the VMM itself

Every other detection in Shukra is about a guest's network traffic, or about a connection QEMU made. This one is about what a QEMU process does **on the host**: the files it opens and the calls it makes. A QEMU process in steady state is quiet in a particular way. Its disk images are already open, it talks to the guest through memory, and it never calls `ptrace`, `mount`, `unshare`, `setns` or loads a kernel module. So when a QEMU process, or a shell it started, does one of those things, something is wrong: a guest that escaped into the VMM, or a person with a shell in it.

The `vmm` program watches for exactly that, with no configuration. On the reference hypervisor ten running QEMU processes made no call of that kind in thirty seconds, so a report is rare and worth reading. Reference: [VMM tripwires](../vmm-tripwires.md). This tutorial shows that it is on, how to change what counts, how to make it fire on purpose without touching a real VM, and how to read what it says.

It is a **tripwire, not a sandbox**. It says a VMM did something. It does not stop it.

## 1. Check that it is on

```bash
shukractl programs
```

```text
vmm       attached    15 hooks
```

That is the whole check. It is on by default. `-vmm-tripwires=false` (in `SHUKRA_EXTRA_ARGS`, see [deploy](03-deploy.md#other-daemon-options)) does not load it, and then the line reads:

```text
vmm       detached    turned off with -vmm-tripwires=false
```

A syscall tracepoint your kernel lacks shows as `N/15 hooks` with the reason, as `kvm` does on arm64, and `shukractl doctor` warns about it. There is no `shukractl trace vmm`: this program has no counters, only events and detections.

**What it costs.** It fires on every file open on the host, so its first job is to find out whether the caller is a VMM or descends from one. On the reference host, about 8,100 tracepoint hits a second, that was about 183 ns per open and 0.161% of one core. It scales with how many opens the host does: at 100,000 opens a second it would be about 2% of a core. A host that busy can turn it off.

## 2. What it watches and what it reports

**Which processes.** Every QEMU process the daemon's scan finds (or a FluxVM backend), and **anything they started, however deep**: a shell, the program the shell ran, what that ran. A shell that starts a background job and exits does not shake it off, because descent is recorded when a process is created.

**What it reports.** Each of these is an event, and only some become detections:

| Event | What it is | Becomes a detection |
|---|---|---|
| `vmm_file_open` | A file opened: the path as given, the program, its pid, whether it asked to write | `vmm-sensitive-open` (critical, configurable) when the path is on the sensitive list |
| `vmm_syscall` | One of ten calls, with the arguments in words | `vmm-syscall`: critical for `ptrace`, `process_vm_writev`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`; high for `process_vm_readv`, `mount`, `unshare`, `setns` |
| `vmm_syscall` named `flood` | A VMM made more than 300 calls in a second, and the rest were not listed | `vmm-flood` (critical) |

The built-in sensitive list is `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` and `/etc/sudoers.d`, `/etc/ssh`, `/root/.ssh`, `/home/*/.ssh`, `/proc/*/mem`, `/proc/kcore`, `/proc/kmem`, `/proc/sysrq-trigger`, the docker and containerd sockets, `/etc/kubernetes`, the k3s and rancher server directories, and **`/etc/shukra` and `/var/lib/shukra`**, which hold the API key and the daemon's own data. A pattern matches the path and everything under it, on a segment boundary: `/etc/ssh` covers `/etc/ssh/sshd_config` and not `/etc/ssh2`. A path is cleaned first, so `/etc/../etc//shadow` is `/etc/shadow`.

All of it is `attribution: qemu-process` and `guest_attributed: false`. It is what the VMM (or a process it started) did on the host. It is not something a process inside the guest did, and it should not be briefed as that.

A VMM that is starting or stopping does open a few files (`/proc/sys/vm/overcommit_memory`, `/sys/devices/system/cpu/online`, its own disk image as it goes away). Those are events, not detections.

## 3. Look at a healthy host

This only reads, so it is safe on a production hypervisor:

```bash
shukractl watch --once | grep vmm_
shukractl security web-01
```

On a settled host you will often see nothing from the first command, and `no detections` (or none named `vmm-...`) from the second. If a VM has just started or stopped you may see its ordinary opens:

```text
2026-09-20T04:41:07.221Z  vmm_file_open  qemu-process  vm=web-01  dst=<nil>  path=/sys/devices/system/cpu/online  comm=qemu-system-x86  pid=2211
```

(`dst=<nil>` is only how the CLI prints a field these events do not have.) Ordinary opens like that one are not on the sensitive list, so the second command stays quiet. If it names a `vmm-` detection, go to [reading a detection](#6-read-a-vmm-sensitive-open) now.

## 4. Change what counts: the `vmm:` section

You do not need this section to have tripwires. It only changes what is judged. All of it is optional:

```yaml
vmm:
  paths: [/srv/secrets, /var/lib/customer-data]   # sensitive as well as the built-in list
  ignore: [/var/lib/customer-data/images]          # never reported, even under a path above
  syscalls: [ptrace, setns, mount]                 # report only these calls (default: all ten)
  severity: high                                   # of a sensitive open (default critical)
```

| Key | What it does |
|---|---|
| `paths` | Absolute paths to add. `*` is one whole path segment (`/home/*/.ssh`), and a path matches itself and everything under it |
| `ignore` | Paths never reported as sensitive. It wins over the defaults and over `paths`. This is how a VM image kept under a directory the list names does not raise a detection every time it is opened |
| `syscalls` | Which calls are reported: `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`. The opens are not in this list: they are governed by `paths` and `ignore` |
| `severity` | Of a sensitive open only: `low`, `medium`, `high` or `critical`. The calls keep their own severities |
| `defaults` | `false` drops the built-in paths, so only your `paths` are sensitive. That also drops `/etc/shukra` and `/var/lib/shukra` |

`defaults: false` looks like this, and is rarely what you want:

```yaml
vmm:
  defaults: false
  paths: [/srv/secrets, /home/*/.ssh]
```

Put the section in `/etc/shukra/detections.yaml`, then check and reload as for any rules change:

```bash
shukractl rules check /etc/shukra/detections.yaml
sudo systemctl reload shukra
```

`rules check` runs the daemon's own strict parser, so a misspelled key is refused, not quietly ignored:

```text
error: bad.yaml: yaml: unmarshal errors:
  line 2: field path not found in type detect.VMMConfig
```

A path that is not absolute, a `*` inside a name (`/tmp/x*`), a lone `/` and an unknown syscall are refused too, each with its reason. A file that fails on `reload` leaves the previous rules in force, and `shukractl doctor` reports `The detection file did not reload`. `rules check` prints only `ok` for a good file and does not list the `vmm:` settings, so to see that yours took effect, make it fire (next section).

## 5. Make it fire on purpose, without touching a real VM

You cannot trigger this from inside a guest: it watches the QEMU process on the host, and a guest that behaves does nothing there. What you can do without touching a real VM is:

**a. Confirm a real guest raises nothing.** [`scripts/test-live-guest.sh`](../../scripts/test-live-guest.sh) is the test built for a working hypervisor. It boots two small disposable guests with fluxvm (each has a 30-minute time to live as a backstop), checks that the `vmm` program is attached, that the guest's QEMU is on the kernel's watched list, and that **a real QEMU raised no tripwire detection** while it booted, ran and talked to its peer. It never touches another VM and never isolates anything, and it deletes what it made. Read [the live guest test](../testing.md#the-live-guest-test) for the environment and what it leaves behind (detections that name a `shukra-live-<pid>` VM, which reach your alert sinks, so tell whoever watches them). It needs fluxvm, `/dev/kvm` and `sudo`.

**b. Make it fire with a stand-in.** A stand-in is a process that only *looks* like a QEMU process to the daemon: its command line starts with `qemu-system-x86_64` and it has a `-name`. It has no guest, no tap and no disk, and it never touches a real VM. A program it starts opens a sensitive file and makes one call. That is the same technique the test rig uses, in its section 16.

Do this on a lab host, or tell whoever receives your alerts first: it raises real detections, and they name a VM called `tripwire-demo` and go to every sink. If you have a `responses:` rule that answers `vmm-` detections ([below](#7-tie-it-to-a-response)), it will propose an action for the stand-in, and you will need to reject it. Run it as an **ordinary user**, not root.

```bash
DEMO="$(mktemp -d)"
cat > "$DEMO/standin.sh" <<'EOF'
#!/bin/bash
sleep 10                                    # the daemon rescans every 2 s: wait until it has noticed this process
for f in /etc/shadow /tmp/tripwire-demo-secret /etc/hostname; do
  cat "$f" >/dev/null 2>&1                  # a program the "VMM" started opens a file. The open is seen before the kernel decides,
  sleep 1                                   # so it does not matter that this user may not read it
done
unshare -m true 2>/dev/null                 # and makes a call a VMM never makes
sleep 20
EOF
bash -c "exec -a /usr/bin/qemu-system-x86_64 bash $DEMO/standin.sh -name tripwire-demo" &
```

Give it fifteen seconds, then:

```bash
shukractl vms
shukractl security tripwire-demo
shukractl watch --once | grep 'vm=tripwire-demo' | grep vmm_
```

(The events share a part of the daemon's event list with `exec` and `exit`. On a host where VMMs start many programs an event can be pushed out within minutes, so if the third command shows nothing, run `shukractl watch` in another terminal before you start the stand-in, or ask the VM's own recorder, which keeps 4,096 events: `shukractl recorder tripwire-demo --window 5m --json`.)

`vms` lists `tripwire-demo` with `runtime=qemu` and `taps=-`. `security` prints a header (which depends on whether you set an allow list) and then, in some order:

```text
  critical    cat (pid 4321) in tripwire-demo's VMM process tree opened /etc/shadow, which matches /etc/shadow: a VMM has no reason to  guest_attributed=false  attribution=qemu-process
  high    unshare (pid 4325) in tripwire-demo's VMM process tree called unshare (new mount namespace): a VMM has no business doing that  guest_attributed=false  attribution=qemu-process
  high    unexpected exec cat  guest_attributed=false  attribution=qemu-process
```

The severity is first, then the destination (empty here, since these have none), then the message. The pids and the extra `unexpected exec` lines for `unshare` and `sleep` will differ on your host.

Three outcomes, from three opens:

- `/etc/shadow` is on the built-in list: a critical `vmm-sensitive-open`.
- `/etc/hostname` is an event (in `watch`) and **no** detection: the tripwire reports an ordinary open and does not judge it.
- `/tmp/tripwire-demo-secret` is an event and no detection **until** you add it. Put this in the rules file, check and reload, and run the stand-in again:

  ```yaml
  vmm:
    paths: [/tmp/tripwire-demo-secret]
  ```

  You then get a second `vmm-sensitive-open`, naming `/tmp/tripwire-demo-secret`. That is how you check a `paths` entry of your own. `ignore` is checked the same way: add `ignore: [/etc/shadow]` and `/etc/shadow` is an event and no detection. A repeat of a detection inside the suppression time is held back either way, so put `suppress: 0s` at the top of the rules file while you test (and take it out again), or wait five minutes between runs.

`unexpected-exec` is Shukra's older check for a program a VMM started that is not on its allow list. It is in that output because the stand-in's `cat` is exactly that, and it is a useful second signal for real (below). A second run inside the suppression time (five minutes by default) is held back: one detection per VM, file and program.

When you are done:

```bash
kill %1 2>/dev/null; rm -rf "$DEMO"
```

The stand-in ends by itself after about half a minute, and the VM leaves `shukractl vms` a few scans later. Its detections stay in the event list and the log.

**Do not** run `scripts/test-tap.sh` (`make test-tap`), which contains this test as its section 16, on a production hypervisor. It shares the tap program's pin directory with the daemon and its cleanup removes every pinned link on the host, which lifts every isolation and every enforcing egress policy. It is for a machine that is not serving VMs. See [testing](../testing.md#never-run-it-on-a-live-hypervisor).

## 6. Read a `vmm-sensitive-open`

Take the first line above apart:

```text
cat (pid 4321) in web-01's VMM process tree opened /etc/shadow, which matches /etc/shadow: a VMM has no reason to
```

| Part | Says |
|---|---|
| `cat (pid 4321)` | The program (its `comm`) and its pid. Not necessarily QEMU: a program the VMM started |
| `in web-01's VMM process tree` | The kernel named the VMM this process descends from, so the VM is web-01 |
| `opened` or `opened for writing` | Whether the open asked to write |
| `/etc/shadow` | The path after cleaning (`..` and repeated slashes resolved) |
| `which matches /etc/shadow` | The pattern on the list. For `/etc/shadow/x` it would still say `/etc/shadow`; `/proc/1/mem` would say `/proc/*/mem` |

The event beside it (`shukractl watch --json --once | grep vmm_file_open`) has the path **as the process gave it**, the syscall (`openat`, `openat2` or `open`) and `write`. A relative path is resolved from `/proc` while the process is still there, and says so in its `detail`. A short-lived process is often gone by then, so a relative path stays as given and cannot be judged: `cd /etc; cat shadow` from a process that has exited is `shadow`.

**How to think about it.**

1. **Who is the process?** A `cat`, a `sh` or a `python3` under a QEMU is not QEMU. Look for an `unexpected-exec` detection at the same time: for a program the VMM started directly, `shukractl security <vm>` shows it, which tells you what launched the shell. A shell under QEMU and a sensitive open together is the case this exists for.
2. **What was around it?** `shukractl recorder <vm> --window 10m` and `shukractl incident <vm> --at -10m --out ticket.json` collect the events, detections and the verdict for the window ([tutorial 9](09-after-the-fact.md)). The bundle names the paths, so treat it as sensitive.
3. **Is it yours?** A backup or monitoring agent that legitimately reads a listed path shows up as the same program opening the same path every night. Add it to `ignore` (or take the path off with `defaults: false` and your own list) rather than living with the alert.
4. **What it cannot tell you.** It is a tripwire. The path is read when the call starts, a symlink is not followed (`/tmp/x` pointing at `/etc/shadow` is `/tmp/x`), and a VMM that opens nothing sensitive is not seen at all. A quiet `vmm` program is not proof of a healthy VMM.

A `vmm-syscall` reads the same way. `ptrace` says the request and the process (`request 16 (ATTACH) on pid 1`), `process_vm_writev` and `process_vm_readv` whose memory, `unshare` which namespaces and `setns` which descriptor. A `vmm-flood` says a VMM made more than 300 calls in a second: what was inside the flood is not listed, and that it flooded is the detection.

## 7. Tie it to a response

A detection tells a person. A [response](../responses.md) can go further, and the only thing it can do is **isolate the VM**. By default it only *proposes*, and a person approves.

```yaml
responses:
  - name: contain-tampered-vmm
    rules: [vmm-sensitive-open, vmm-syscall, vmm-flood]
    action: isolate
    mode: propose            # a person approves. Keep it this way
    expire: 1h               # a proposal that nobody decides lapses
guardrails:
  never_isolate: [db-primary]
```

```bash
shukractl rules check /etc/shukra/detections.yaml
sudo systemctl reload shukra
```

`rules check` prints `contain-tampered-vmm (propose)` under `responses`. When a tripwire fires, the daemon records an action with the incident bundle a person will decide on, and announces it as an `action-proposed` detection, which goes to your webhook:

```bash
shukractl actions                 # what waits for a decision
shukractl actions --bundle a-1    # the evidence: verdict, detections, recorder events
shukractl approve a-1             # isolate the VM
shukractl reject a-1              # do nothing
```

The **Actions** page in the console does the same, with a confirmation that names the VM.

Be clear about what isolating buys you here. It cuts the *guest's* network, except the management allow list. The process that opened `/etc/shadow` is already on the host, and isolation does not stop it. It stops the guest's traffic (and so anything the intruder is sending out through it), and it buys time to preserve evidence. Deciding what to do with a host that a VMM has touched is a person's call.

Three cautions:

- **Not `mode: enforce`.** A response that acts on its own on a tripwire will isolate a healthy VM the first time a rule is wrong (an image under a listed path, a monitoring agent). Try a response as `dry_run: true` first, and keep the guardrails.
- **It needs the management allow list.** Without `-isolate-allow`, every action is `refused` with that reason, and `shukractl doctor` says so under `responses`. The flag also lets anyone holding the admin key cut a VM off, so if `shukractl doctor` reports the well-known dev key or plain HTTP on a non-loopback address, fix that first. [Tutorial 10, step 5](10-egress-policy.md#5-give-enforcement-its-floor-the-management-allow-list) has the warning and the way to set the flag.
- **A proposal is not a page.** Nobody is paged unless a sink delivers `action-proposed` and `vmm-*` to someone who reads it. [Alert sinks](07-alert-sinks.md) has the setup and how to test it.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `vmm` is `detached` with `turned off with -vmm-tripwires=false` | It was turned off on purpose. `shukractl doctor` cannot tell that from a failure and warns while the flag is on. Remove the flag from `SHUKRA_EXTRA_ARGS` and restart |
> | `vmm` is `detached` with `CO-RE objects are not linked in this binary` | The binary was built without BPF: [attach traces](02-attach-traces.md) |
> | `vmm` is `detached` with another reason | The kernel refused it. `shukractl doctor` and the daemon log have the error. The other programs still run |
> | The stand-in never appears in `shukractl vms` | Its command line must start with `qemu-system`. Check with `pgrep -af tripwire-demo`. The daemon rescans every two seconds |
> | The stand-in is listed, but no `vmm-` detection | The opens happened before the daemon noticed it: raise the first `sleep` in the script. Also check `shukractl security tripwire-demo` and not `shukractl security` of another VM |
> | An open you expected is not reported | `ignore` wins over everything. Check `ignore`, and that `paths` are absolute |
> | `field path not found in type detect.VMMConfig` | The key is `paths`, not `path` |
> | A real VM keeps raising `vmm-sensitive-open` on its own image | The image is under a directory the list names: add it to `ignore` |
> | A `vmm-flood` on a busy VMM | More than 300 opens and calls in a second is the limit. That a VMM does it is the finding |
