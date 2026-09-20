# VMM tripwires: what a QEMU process should never do

A QEMU process in steady state is quiet in a particular way: it has its disk images open already, it talks to the guest through memory, and it makes no calls that a normal program makes to reach around itself. So when one **opens a file, or calls `ptrace`, `mount`, `unshare`, `setns`, or loads a kernel module**, or when a shell it started does, something is wrong: a guest that escaped into the VMM, or a person with a shell in it.

The `vmm` program watches for exactly that, with no configuration. On the reference hypervisor, ten running QEMU processes made **no** `openat`, `openat2`, `open`, `ptrace`, `mount`, `unshare` or `setns` call in thirty seconds, so any one is worth a look and the reports are very few.

## What is watched

- **Which processes.** The QEMU processes of the scan (or a FluxVM backend), the same set the scheduler program watches, and **anything they started, however deep**: a shell a VMM started, the program the shell ran, and what that ran. Descent is recorded when a process is *created* (a fork by a VMM, or by something that descends from one, marks the child; its exit clears it), so a shell that starts a background job and exits, which re-parents the job to init, has not shaken it off. The kernel names the VMM each process descends from, so the event belongs to that VM. A process that was already running when a VMM was first seen has no such record, and is found through its parents, up to three of them.
- **What is reported.**

| Event | What it is |
|---|---|
| `vmm_file_open` | A file opened: the path as the process gave it, the program (`comm`), its pid, whether it asked to write, and which VMM |
| `vmm_syscall` | `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`, with the arguments in words (`request 16 (ATTACH) on pid 1234`, `new mount, user namespace`) |
| `vmm_syscall` named `flood` | A VMM made more calls in a second than the tripwire reports. `count` is how many were not |

All are `attribution: qemu-process` and `guest_attributed: false`: they are what the VMM did, not the guest.

The fields, as they appear in `GET /api/v1/events` and `shukractl watch --json`:

| Field | What it is |
|---|---|
| `kind` | `vmm_file_open` or `vmm_syscall` |
| `vm` | The VM whose VMM this is. Empty when the VMM is no longer in the scan, and then no detection is raised, since there is no VM to say it about |
| `tgid` | The VMM's pid |
| `pid`, `comm` | The process that made the call, and its program name (15 characters, as the kernel keeps it). Not the VMM's unless the VMM itself made it |
| `path` | `vmm_file_open`: the path as the process gave it, printable, and made absolute when a relative one could be resolved (`detail` then says how) |
| `write` | `vmm_file_open`: the open asked to write, create or truncate. Not known for `openat2`, whose flags are in a structure the program does not read, so it is never set there |
| `syscall` | The call: `openat`, `openat2`, `open`, one of the calls above, or `flood` |
| `detail` | The call's arguments in words, or how a relative path was resolved |
| `count` | `flood` only: how many calls were not reported |

`shukractl watch` ends a `vmm_file_open` line with `path=`, `comm=` and `pid=` (and `write`), and a `vmm_syscall` line with `syscall=`, `comm=`, `pid=` and the detail. The events sit in the same share of the event list as `exec` and `exit` (256 of the 2,048), so on a host where VMMs start many programs a rarer event can be pushed out of the list within minutes; the per-VM flight recorder (4,096 events) and an [incident bundle](tutorials/09-after-the-fact.md#4-one-file-for-the-ticket), which is cut from it, keep them longer. A detection is kept in the detection list (256 guaranteed) and, with `-data-dir`, in `detections.jsonl`.

## What becomes a detection

An open is judged in the daemon, not the kernel, so the list can change without a new program.

| Detection | When | Severity |
|---|---|---|
| `vmm-sensitive-open` | A watched process opens a path that matches the sensitive list | critical (configurable) |
| `vmm-syscall` | A watched process makes one of the calls above | critical for `ptrace`, `process_vm_writev`, `init_module`, `finit_module`, `kexec_*`; high for `process_vm_readv`, `mount`, `unshare`, `setns` |
| `vmm-flood` | A VMM, with everything it started, made more than 300 opens and calls in a second, so the tripwire could not report them all | critical |

The built-in sensitive list: `/etc/shadow`, `/etc/gshadow` (and their `-` backups), `/etc/sudoers` and `/etc/sudoers.d`, `/etc/ssh`, `/root/.ssh`, `/home/*/.ssh`, `/proc/*/mem` and `/proc/*/task/*/mem`, `/proc/kcore`, `/proc/kmem`, `/proc/sysrq-trigger`, the docker and containerd sockets, **`/etc/shukra` and `/var/lib/shukra`** (the API key and the daemon's own data), `/etc/kubernetes`, `/var/lib/rancher/k3s/server` and `/etc/rancher`. A pattern matches the path and everything under it, on a segment boundary (`/etc/ssh` is `/etc/ssh/sshd_config` and not `/etc/ssh2`), and `*` stands for exactly one segment.

**A VMM that is starting or stopping does open a few files**, and they are events and not detections. On the reference host a KVM guest's QEMU opened `/proc/sys/vm/overcommit_memory` and `/sys/devices/system/cpu/online` as it started and its own disk image (`root.qcow2`) as it went away; none is on the sensitive list, so the tripwire raised nothing while it booted, ran and talked to its peer. If your VMs open something else as they start, or keep their images under a directory the list names, that is what `ignore` is for.

A path is **cleaned first**, so `/etc/../etc//shadow` is `/etc/shadow`. A detection is held back per VM, file and program (per call for a syscall) for the rules file's `suppress` time (5 minutes by default), so a shell that reads a file twice is one detection. The events are not held back: every open the tripwire reports is an event.

The limit of 300 is **per VMM, for all its processes together, and counts every open**, sensitive or not, because the kernel cannot tell them apart. The flood is reported by the first call the VMM makes after the second is over, so `vmm-flood` can arrive a second or more after the calls it describes (and, if the VMM's tree then goes silent, it waits for the next call), and it names the program that made that call, which is not necessarily the one that flooded.

```text
vmm-sensitive-open  critical  cat (pid 4321) in web's VMM process tree opened /etc/shadow, which matches /etc/shadow: a VMM has no reason to
vmm-syscall         critical  gdb (pid 77) in web's VMM process tree called ptrace (request 16 (ATTACH) on pid 1): a VMM has no business doing that
```

## Where it shows

| Surface | What |
|---|---|
| `shukractl watch` | Every `vmm_file_open` and `vmm_syscall` as it happens, and every detection |
| `shukractl security <vm>` | The VM's detections, `vmm-*` among them |
| `GET /api/v1/events`, `/detections`, `/recorder?vm=` | The events and detections, as JSON |
| `shukractl incident <vm> --at -10m` | The window's detections and recorder events, in one file for a ticket. It holds the paths that were opened, so treat it as you would the event list |
| An alert sink | Each detection, as for any other rule |
| `shukractl programs` | `vmm  attached  15 hooks` |

There is no counter and no Prometheus series for the tripwires: a healthy host produces almost no events, so alert on the detections (`shukra_detections` and the sinks) and, if you want to know the program is loaded, on `shukra_program_attached{program="vmm"}`.

## Changing what counts

The `vmm:` section of the rules file is optional and only changes what is judged:

```yaml
vmm:
  paths: [/srv/secrets]          # sensitive as well as the built-in list
  ignore: [/root/images]         # never reported: a disk image kept under a directory above
  syscalls: [ptrace, setns]      # report only these (default: all of them)
  severity: critical             # of a sensitive open
  defaults: true                 # false leaves only `paths`
```

`ignore` wins over everything. It is how a VM image that lives under a directory the list names (a home directory, say) is not a detection every time it is opened. A path must be absolute, `*` must be a whole segment, `/` alone is refused (it would match everything), and a mistake keeps the previous rules, like every rules error.

`shukrad -vmm-tripwires=false` does not load the program at all; it reports `detached: turned off with -vmm-tripwires=false`. `shukractl doctor` cannot tell a deliberate off from a failure, so it lists `vmm` as a detached program (warn) for as long as the flag is on.

The rules are validated when the file is read, and a mistake keeps the previous rules (`shukractl rules check <file>` says which):

| Key | Accepts | Refused when |
|---|---|---|
| `paths` | Up to 256 absolute paths or patterns | One is not absolute, is `/`, is over 256 bytes, or has a `*` that is not a whole segment (`/etc/ss*`) |
| `ignore` | The same | The same |
| `syscalls` | Any of `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load` | A name that is not one of them. Case does not matter. An empty list means all |
| `severity` | `low`, `medium`, `high`, `critical` | Anything else. It applies to sensitive opens only: a call's severity is fixed by the call |
| `defaults` | `true` (the default) or `false` | |

A `vmm:` section that names some of these leaves the rest as it was. The response to a wrong file is the same as for every rules error: `systemctl reload shukra` logs it and the previous rules stay in force, and `shukractl doctor` reports `rules` as failed.

## What it costs

The tracepoints fire for **every** process on the host, so the first thing each does is find out whether the caller is a VMM or descends from one: a lookup for itself, one in the table of descendants, and, for a process that is in neither, a walk through up to three parents. Two more hooks keep that table (a fork, and an exit) and fire on every process creation and exit. Measured on the reference host (Intel Xeon E-2336, Linux 6.8, about 8,100 tracepoint hits a second across a k3s and Cilium node), with an empty watched list so every call takes the slow path:

| | |
|---|---|
| Per call | about **183 ns** for `openat`, about 860 ns for a fork and 550 ns for an exit (about 100 a second each here) |
| Whole program | **0.161% of one core** |

That is inside the 0.2% the design allowed, and it scales with how many opens the host does: **at 100,000 opens a second it would be about 2% of a core**. A host that busy can turn it off with `-vmm-tripwires=false`; the cost is not in the events, which are almost none, but in deciding for every open that it is not a VMM's. The cost of a call by a VMM is more, and bounded: a per-VMM limit of 300 reported calls a second.

## How do I know it works

A steady-state VMM opens nothing, so on a healthy host the honest evidence is quiet. What you can check:

1. **It is loaded.** `shukractl programs` says `vmm  attached  15 hooks`: 13 syscall tracepoints, and the fork and exit hooks that keep the record of descent. `attached  14/15 hooks; ...` means a tracepoint this kernel lacks, and doctor warns (`program-vmm`); if the missing one is the fork or exit hook, descendants are found only through their parents, up to three of them.
2. **It sees a VMM.** Start a disposable VM while `shukractl watch` runs. A handful of `vmm_file_open` events appear as it starts and as it stops (the files listed under [What becomes a detection](#what-becomes-a-detection)) and no detection: a real KVM guest's QEMU raises none while it boots and runs. That is the same check the live guest test makes.
3. **It raises a detection.** Nothing is safe to run inside a real VM's process tree, which is exactly what it exists to find. The [walkthrough](tutorials/11-vmm-tripwires.md#5-make-it-fire-on-purpose-without-touching-a-real-vm) makes it fire with a stand-in process that only looks like QEMU to the daemon, on a lab host. The proof it is right is in [Checked](#checked): `make test-tap` (section 16) runs a fake VMM whose children open sensitive files and make each call, on a machine that is not running Shukra, and `TestKernelIntegrationVMMTripwires` loads the real program and makes the calls itself.
4. **The rules file is read as you meant.** `shukractl rules check <file>` accepts it, and a path you added shows up as a `vmm-sensitive-open` detection when a test process opens it (the rig's rules file does this with `/tmp/rig-vmm-secret`).

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `vmm  detached  turned off with -vmm-tripwires=false` | Someone set the flag (check `SHUKRA_EXTRA_ARGS` in `/etc/shukra/env`) | Remove it and restart, or leave it off on a host that opens 100,000 files a second |
| `vmm  detached` with an error | The program failed to load | `shukractl programs` gives the reason (the CO-RE programs need kernel BTF). The other programs are unaffected |
| `vmm  attached  N/15 hooks; ...` | Some tracepoint is missing on this kernel | The rest work. Fork or exit missing means lineage is found through three parents only |
| A `vmm-sensitive-open` for a VM's own disk image | The image lives under a directory the list names (a home directory, `/root`) | `ignore: [<the image directory>]` |
| A `vmm-flood` with no sensitive open | A tool in the VMM's tree opened more than 300 files in a second. Not necessarily an attacker | The events before it say what it was; `comm` on the detection is only the program that made the first call after the flood |
| A detection names a program you cannot find | The program has exited. A relative path is left as given when its process was gone before the event was read | The event's `pid` and `comm`, and the recorder around it (`shukractl recorder <vm>`) |
| A path in an event that looks wrong or is cut | A path is copied up to 255 characters and shown with every non-printable byte as `?` | The events are as the kernel gave them, not as the filesystem has them |
| A `vmm_*` event with no VM, and no detection | The VMM is no longer in the scan (the VM stopped) | Nothing: there is no VM to name |
| Events but no detection for a file you consider sensitive | It is not on the list, it is under an `ignore` entry (which wins), it is a relative path that could not be resolved, or `defaults: false` removed the built-in list | `shukractl rules check`, and the event's `path` |
| No events from a VM's shell you know ran | The shell was started before the VMM was seen and is more than three parents away, or the call is not one the tripwire watches | See [What it does not see](#what-it-does-not-see) |

## Limits

All in `bpf/vmm.bpf.c` and `internal/detect/vmm.go`.

| What | Limit |
|---|---|
| Reported calls | 300 a second per VMM and everything it started, opens and calls together. More is counted and reported once as a flood |
| VMMs watched | 4,096 (`vmm_watched`) |
| Descendants remembered | 8,192 (`vmm_desc`, an LRU) |
| VMMs with a rate record | 1,024 (an LRU) |
| Parents walked for a process that is not recorded | 3 |
| Path copied | 255 characters and a NUL |
| Event ring | 256 KiB. A full ring drops the newest event in the kernel, and nothing counts that |
| `paths` and `ignore` | 256 entries each, each at most 256 bytes |
| Program name | 15 characters, as the kernel keeps `comm` |
| Calls watched | 13 syscall tracepoints, plus the fork and exit hooks |

## What it does not see

It is a **tripwire, not a sandbox**.

- **The path is read when the call starts.** One that changes after that is not seen, and a symlink is not followed: `/tmp/x` that points at `/etc/shadow` is `/tmp/x`.
- **A relative path is resolved from `/proc` while the process is still there.** A short-lived process is often gone by the time the event is read, and then the path stays as it was given, and cannot be judged: `cd /etc; cat shadow` from a process that has exited is `shadow`. (The event says when it resolved one, and how.)
- **A process that was already running when its VMM was first seen** is found through its parents, up to three, because nothing recorded its lineage. This matters only for a shell someone left running before Shukra started watching.
- **A VMM is watched from the next scan after it appears**, which is at most two seconds. Something it does in that first moment is not seen.
- **A process table that overflows forgets.** Descendants are kept in a fixed-size table of 8,192, least recently used first, so a VMM that forks more than that between two of a process's calls could push a slow one out; such a process is found again through its parents while they live. That a VMM forks that much is itself worth a look, and Shukra's [exec detection](tap.md#what-each-program-attributes) sees what a VMM starts.
- **A VMM that does none of these** is not seen at all: it does not have to open a file to be compromised.
- **It sees the call, not what became of it.** An open that fails for want of permission is still reported, because the tripwire fires before the kernel decides. A detection means a VMM process tried, not that it read the file.
- **An `execve` is not a tripwire.** What a VMM starts is seen by the [exec detection](tap.md#what-each-program-attributes), which is a separate check with its own allow list; the tripwires start from what those processes then open and call.
- **A flood hides nothing that was reported before it**, but calls past the limit are counted and not listed, so what is inside a flood is not visible. That a VMM flooded is itself the detection.
- **Not other hosts' VMMs**: only the VMM processes of this host's scan.

## From a tripwire to a response

A tripwire is a detection like any other, so a [response](responses.md) can name it. The sensible one proposes, so a person reads the [incident bundle](tutorials/09-after-the-fact.md#4-one-file-for-the-ticket) the proposal carries before anything is done:

```yaml
responses:
  - name: look-at-vmm
    rules: [vmm-sensitive-open, vmm-syscall, vmm-flood]
    action: isolate
    mode: propose
    expire: 30m
guardrails:
  never_isolate: [db-primary]
```

Be clear about what that does. **Isolation cuts the guest's network at its tap. It does not stop a process in the VMM's tree**, so it contains a guest that is talking out, not a shell on the host. The detection and the bundle are the evidence; isolating is a decision for a person who has read them, which is why `mode: enforce` would have to name these rules explicitly and is not recommended for them.

## Checked

- `TestKernelIntegrationVMMTripwires` loads the real program and checks it against calls the test makes itself, with the test process standing in for a QEMU process: a file it opens, one a child opens, eight levels down, a process whose parent has exited, one that was already running before the VMM was seen, an unwatched process, each call, the limit and the flood report, a long path, a relative one. It runs in CI, and on a production host too, since its maps are its own. The kernel program was mutation-checked: fifteen deliberate breakages of the C, each caught.
- Section 16 of `scripts/test-tap.sh` runs the daemon against a fake VMM whose child opens sensitive files and makes each call, and checks the detections, the cleaning of a path, the rules-file overrides, the flood, that an unwatched process is not seen, and the off switch.
- The live-guest test checks that a real KVM guest's QEMU is on the kernel's watched list and raises no tripwire detection while it boots and runs, and then asks that QEMU, over its own QMP socket, to open `/etc/shadow` and requires a critical `vmm-sensitive-open` for that VM, attributed to the VMM.

## See also

The [walkthrough](tutorials/11-vmm-tripwires.md) runs the tripwires against a fake VMM you start yourself. [Responses](responses.md), which can propose isolating a VM when a tripwire fires. [Detection rules](tutorials/06-watchlist.md), for `suppress` and the other sections of the rules file. [Investigate after the fact](tutorials/09-after-the-fact.md), for the incident bundle. [Guest traffic and isolation](tap.md#what-each-program-attributes), for how a VMM and its processes are joined to a VM. [Doctor](doctor.md), for `program-vmm` and `rules`.
