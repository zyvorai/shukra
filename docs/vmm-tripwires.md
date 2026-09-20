# VMM tripwires: what a QEMU process should never do

A QEMU process in steady state is quiet in a particular way: it has its disk images open already, it talks to the guest through memory, and it makes no calls that a normal program makes to reach around itself. So when one **opens a file, or calls `ptrace`, `mount`, `unshare`, `setns`, or loads a kernel module**, or when a shell it started does, something is wrong: a guest that escaped into the VMM, or a person with a shell in it.

The `vmm` program watches for exactly that, with no configuration. On the reference hypervisor, ten running QEMU processes made **no** `openat`, `openat2`, `open`, `ptrace`, `mount`, `unshare` or `setns` call in thirty seconds, so any one is worth a look and the reports are very few.

## What is watched

- **Which processes.** The QEMU processes of the scan (or a FluxVM backend), the same set the scheduler program watches, and **anything they started, up to three levels down**: a shell a VMM started, and the program the shell ran. The kernel names the VMM it descends from, so the event belongs to that VM.
- **What is reported.**

| Event | What it is |
|---|---|
| `vmm_file_open` | A file opened: the path as the process gave it, the program (`comm`), its pid, whether it asked to write, and which VMM |
| `vmm_syscall` | `ptrace`, `process_vm_writev`, `process_vm_readv`, `mount`, `unshare`, `setns`, `init_module`, `finit_module`, `kexec_load`, `kexec_file_load`, with the arguments in words (`request 16 (ATTACH) on pid 1234`, `new mount, user namespace`) |
| `vmm_syscall` named `flood` | A VMM made more calls in a second than the tripwire reports. `count` is how many were not |

All are `attribution: qemu-process` and `guest_attributed: false`: they are what the VMM did, not the guest.

## What becomes a detection

An open is judged in the daemon, not the kernel, so the list can change without a new program.

| Detection | When | Severity |
|---|---|---|
| `vmm-sensitive-open` | A watched process opens a path that matches the sensitive list | critical (configurable) |
| `vmm-syscall` | A watched process makes one of the calls above | critical for `ptrace`, `process_vm_writev`, `init_module`, `finit_module`, `kexec_*`; high for `process_vm_readv`, `mount`, `unshare`, `setns` |
| `vmm-flood` | A VMM reported more than 300 calls in a second | critical |

The built-in sensitive list: `/etc/shadow`, `/etc/gshadow` (and their `-` backups), `/etc/sudoers` and `/etc/sudoers.d`, `/etc/ssh`, `/root/.ssh`, `/home/*/.ssh`, `/proc/*/mem` and `/proc/*/task/*/mem`, `/proc/kcore`, `/proc/kmem`, `/proc/sysrq-trigger`, the docker and containerd sockets, **`/etc/shukra` and `/var/lib/shukra`** (the API key and the daemon's own data), `/etc/kubernetes`, `/var/lib/rancher/k3s/server` and `/etc/rancher`. A pattern matches the path and everything under it, on a segment boundary (`/etc/ssh` is `/etc/ssh/sshd_config` and not `/etc/ssh2`), and `*` stands for exactly one segment.

A path is **cleaned first**, so `/etc/../etc//shadow` is `/etc/shadow`. A detection is held back per VM, file and program (per call for a syscall), so a shell that reads a file twice is one detection.

```text
vmm-sensitive-open  critical  cat (pid 4321) in web's VMM process tree opened /etc/shadow, which matches /etc/shadow: a VMM has no reason to
vmm-syscall         critical  gdb (pid 77) in web's VMM process tree called ptrace (request 16 (ATTACH) on pid 1): a VMM has no business doing that
```

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

`shukrad -vmm-tripwires=false` does not load the program at all; it reports `detached: turned off with -vmm-tripwires=false`.

## What it costs

The tracepoints fire for **every** process on the host, so the first thing each does is find out whether the caller is a VMM: one lookup for itself and up to three ancestors. Measured on the reference host (Intel Xeon E-2336, Linux 6.8, about 7,700 opens a second across a k3s and Cilium node), with an empty watched list so every call takes that path:

| | |
|---|---|
| Per call | about **190 ns** for `openat` |
| Whole program | **0.147% of one core** |

That is inside the 0.2% the design allowed, and it scales with how many opens the host does: **at 100,000 opens a second it would be about 2% of a core**. A host that busy can turn it off with `-vmm-tripwires=false`; the cost is not in the events, which are almost none, but in deciding for every open that it is not a VMM's. The cost of a call by a VMM is more, and bounded: a per-VMM limit of 300 reported calls a second.

## What it does not see

It is a **tripwire, not a sandbox**.

- **The path is read when the call starts.** One that changes after that is not seen, and a symlink is not followed: `/tmp/x` that points at `/etc/shadow` is `/tmp/x`.
- **A relative path is resolved from `/proc` while the process is still there.** A short-lived process is often gone by the time the event is read, and then the path stays as it was given, and cannot be judged: `cd /etc; cat shadow` from a process that has exited is `shadow`. (The event says when it resolved one, and how.)
- **Four levels down is not seen.** A VMM, its shell, that shell's child and *its* child is the deepest that is reached. Shukra's [exec detection](tap.md#which-process) still sees what a VMM starts.
- **A VMM that does none of these** is not seen at all: it does not have to open a file to be compromised.
- **A flood hides nothing that was reported before it**, but calls past the limit are counted and not listed, so what is inside a flood is not visible. That a VMM flooded is itself the detection.
- **Not other hosts' VMMs**: only the VMM processes of this host's scan.

## Checked

- `TestKernelIntegrationVMMTripwires` loads the real program and checks it against calls the test makes itself, with the test process standing in for a QEMU process: a file it opens, one a child opens, three levels down and not four, an unwatched process, each call, the limit and the flood report, a long path, a relative one. It runs in CI, and on a production host too, since its maps are its own. The kernel program was mutation-checked: ten deliberate breakages of the C, each caught.
- Section 16 of `scripts/test-tap.sh` runs the daemon against a fake VMM whose child opens sensitive files and makes each call, and checks the detections, the cleaning of a path, the rules-file overrides, the flood, that an unwatched process is not seen, and the off switch.
- The live-guest test checks that a real KVM guest's QEMU is on the kernel's watched list and raises no tripwire detection while it boots and runs.
