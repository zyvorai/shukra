# Investigate after the fact

A user says "the VM was slow around three o'clock". It is now half past five. The last minute, which `explain` weighs by default, is no help. This walkthrough asks Shukra what it stored, in four steps, and ends with one file to attach to the ticket.

It needs the daemon to have run with `-data-dir` (the shipped unit does): the stored history is what makes a past time answerable. Without it, every step below says so and stops.

## 1. Ask for the verdict at that time

```bash
shukractl explain osboxes-mint --at 2026-09-20T03:00:00Z --window 30m
shukractl explain osboxes-mint --at -2h30m        # or an age: "two and a half hours ago"
```

`--at` is an RFC 3339 time (any zone) or a negative age. The verdict is built from the snapshot at or before that time and the one a window earlier (`--window` is 5 minutes to 6 hours, 15 minutes by default), with the same code that judges the live minute. Real output from a hypervisor:

```text
EXPLAIN  why was this VM slow?  (window: 5m0s)  (at: 2026-09-20T04:50:27Z)
  resolution: 5m0s snapshots: the verdict stands on 2026-09-20T04:40:53Z and 2026-09-20T04:45:53Z
findings (best supported first)
  [low] no_host_cause: Nothing host-side crossed a threshold. If the guest is slow, the cause may be inside it, which this build does not measure.
  note: Over 5m0s of stored history. Latencies come from log2 buckets, so each can read up to 2x high. They are the QEMU process's, not the guest's.
```

Read the `resolution` line first. Snapshots are 5 minutes apart, so this is a five-minute average around the time you asked about, not the second it happened. A burst shorter than that can be diluted into nothing, and the answer says "nothing crossed a threshold" when that happens. It is a lower bound on trouble, not proof of calm.

`no_host_cause` is a real answer: the host was fine, so look inside the guest. The findings are the same causes as the live `explain`: `host_cpu_contention`, `cpu_preempted`, `noisy_neighbour`, `storage_latency`, `kvm_exit_handling`, `tcp_retransmits`, `guest_traffic_dropped`, `guest_not_reading_nic` and `guest_connects_failing`.

## 2. When there is nothing stored

```text
EXPLAIN  why was this VM slow?  (window: none)  (at: 2026-09-19T22:51:27Z)
findings (best supported first)
  [high] no_history: No snapshot is stored at or before 2026-09-19T22:51:27Z. History starts when the daemon first ran with -data-dir, and only the newest is kept.
```

The one finding is `no_history`, and its summary says which of four things is true: the daemon has no data directory, nothing is that old, the nearest snapshot is more than ten minutes from the time you asked (the daemon was probably not running), or there is not enough before it to make a window. Shukra does not fall back to the lifetime counters and pass them off as the past.

How far back it goes is set by size, not time: about 58 KB per snapshot at ten VMs, so a day or two. `snapshots.jsonl` rolls at 16 MiB like the other logs. See [architecture](../architecture.md#persistence).

## 3. Who was involved

If the finding is `cpu_preempted` or `noisy_neighbour`, ask who took the CPU:

```bash
shukractl trace contention --window 5m
```

```text
  vm=osboxes-debian  preempted=1882612ns over 12 preemptions  (other VMs 0ns, its own threads 0ns, host tasks 1882612ns)
      taken by host tasks: cilium-agent 1031780ns, kubectl 321523ns, hubble-relay 188161ns, containerd-shim 103092ns, tetragon 86460ns
```

For each VM: how much of its preempted time went to other VMs, to its own threads and to host tasks, and which. Under it, each VM that took CPU from others with what it was doing meanwhile (its on-CPU time and KVM exits). A busy culprit is doing it to itself; an idle one is being scheduled badly, which is a placement problem. `contention` is a live view (up to 5 minutes); for a past time the culprits are named in the verdict's evidence. The numbers above are from a host where no VM was the culprit, and the output says so plainly (`other VMs 0ns`) rather than inventing one.

## 4. One file for the ticket

```bash
shukractl incident osboxes-mint --at 2026-09-20T03:00:00Z --window 30m --out osboxes-incident.json
```

```text
wrote osboxes-incident.json (100415 bytes, mode 0600). It names VMs, addresses and DNS names: treat it like the event list.
```

Check the file is private and holds what you expect:

```bash
ls -l osboxes-incident.json                         # -rw-------
jq '{at, window, verdict: [.explain.findings[].cause], detections: (.detections | length), events: (.events | length)}' osboxes-incident.json
```

```text
{
  "at": "2026-09-20T03:00:00Z",
  "window": "30m0s",
  "verdict": ["no_host_cause"],
  "detections": 2,
  "events": 87
}
```

Without `--out` it prints a summary (the verdict, the detections in the window, how many recorder events and isolate requests there were) and says how to get the whole document. The file holds:

| Key | What |
|---|---|
| `explain` | The verdict, as above |
| `detections` | Rule hits for that VM in the window |
| `events` | What the flight recorder saw of that VM in the window, at most 500 |
| `isolations` | Isolate and release requests for that VM in the window |
| `enforcement`, `allowList` | Whether isolate is available and the management networks an isolated VM keeps |
| `programs` | Which programs were attached now |
| `at`, `window`, `generatedAt`, `note` | When it is about, how far back, when it was made, and the warning |

It contains nothing from the daemon's configuration except the allow list: no key, no listen address, no data directory. It is as sensitive as the event list, because it names your VMs, the addresses they talked to and the DNS names they looked up: attach it to a ticket you would be comfortable putting those in.

In the console it is the **At** field and **Download incident bundle** button on the Explain page. The detections in the bundle are every kind the daemon raised in the window, including [VMM tripwires](11-vmm-tripwires.md), [egress policy](10-egress-policy.md) strays and changes, and baseline first sightings, so the bundle for a VM that was contained shows what set it off. A response that proposes an isolation keeps the same kind of bundle for its own decision: `shukractl actions --bundle <id> --out FILE` ([responses](../responses.md)).

## What this cannot tell you

- **The second it happened.** The resolution is 5 minutes. A one-minute stall inside a calm ten minutes may not cross a threshold.
- **The guest.** As everywhere in Shukra: no process inside the guest, and not the guest's own steal counter.
- **Anything before the daemon first stored a snapshot**, or while it was not running.
- **Events that were pushed out.** The flight recorder and the daemon's event list are bounded (the list keeps a share for each kind of event so a busy host cannot push out a guest's), so a very old event may be gone even where counters were stored.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | `no_history` and `No history is kept: the daemon has nowhere to store snapshots` | It ran without `-data-dir`. The shipped unit has it; `shukractl doctor` says `Nothing is kept across a restart` |
> | `no_history` and a time that is too old | Only the newest snapshots are kept (a day or two at ten VMs). The bundle for that time cannot be made, but the events the recorder and the alert sinks still hold can |
> | `no_history` and the nearest snapshot is more than ten minutes away | The daemon was not running then |
> | `at must be an RFC 3339 time, or a negative duration such as -90m` | Use `2026-09-20T03:00:00Z` (any zone, with the offset) or `-90m` |
> | `at is in the future` | The clock on your laptop and on the host disagree, or the date is wrong |
> | `window must be a duration from 5m0s to 6h0m0s` | For a past time the window is 5 minutes to 6 hours. A live `explain --window` is up to 5 minutes, or `lifetime` |
> | `unknown_vm` and `No VM with that name was running at that time` | Check the spelling against `shukractl vms`, and that the VM existed at that moment: the verdict is built from what the snapshot held then |

