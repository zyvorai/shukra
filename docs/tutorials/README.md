# Tutorials

Short, hands-on paths through Shukra. Each one is copy-pasteable, says what you should see after the steps that matter, and ends with a box for when it does not work. Each one assumes you have read the boundary: Shukra observes the hypervisor from outside, and never runs anything inside a guest. It attributes traffic to a VM only when it is seen on that VM's own tap, and it can isolate a VM, or hold it to an egress policy, only when you give it a management allow list.

## Get it running

For anyone building or installing Shukra. Do these in order.

1. [Run it locally](01-run-locally.md) — build the binaries and open the console without attaching BPF. For a developer or anyone who wants to look before they install.
2. [Attach traces](02-attach-traces.md) — compile CO-RE objects on a Linux host with BTF and start `shukrad` as root, and check all seven programs. For someone building on the hypervisor itself.
3. [Deploy a hypervisor](03-deploy.md) — rsync, remote build (or a prebuilt package), systemd, and the checks that mean it worked. For whoever operates the host.

## Use it every day

For operators and on-call. Each stands alone once the daemon is running.

4. [Operator CLI](04-shukractl.md) — the daily commands, JSON, the isolate record, and a map of the rest. Start here after a deploy.
5. [Console](05-console.md) — what each of the sixteen pages is for, and the banner you should not click past. For people who would rather click than pipe JSON.
6. [Detection rules](06-watchlist.md) — destinations, ports, names, exec allow-list, per-VM thresholds, suppression, and the detections that need no rule. For whoever writes the rules file.
7. [Alert sinks](07-alert-sinks.md) — webhook (signed), syslog and file delivery, and how to send a test alert. For whoever has to be told when something fires.

## Investigate

For an operator with a question about one VM.

8. [Find out why a VM's traffic is lost](08-lost-traffic.md) — connection outcomes, kernel drops and Explain together: is the destination refusing, is something on the host dropping, is the guest not reading its NIC, or is it Shukra's own isolation or policy.
9. [Investigate after the fact](09-after-the-fact.md) — a verdict for a past time from stored snapshots, who took the CPU, and one incident bundle to attach to a ticket. For the morning after "the VM was slow at three".

## Protect

For security and platform engineers. These two act on what a VM does, and both are built to be tried before they are believed.

10. [Learn, audit, enforce an egress policy](10-egress-policy.md) — baseline learning, a proposed list, audit mode that drops nothing, then enforcement with a timer that reverts it unless you confirm. Covers the management allow list floor and what to do about an orphan.
11. [Watching the VMM itself](11-vmm-tripwires.md) — the tripwires on QEMU processes, changing what counts, making one fire on purpose without touching a real VM, reading a `vmm-sensitive-open`, and tying it to a response.

## Which one do I want?

| I want to... | Read |
|---|---|
| See what it looks like without a hypervisor | [1](01-run-locally.md) |
| Put it on a hypervisor | [3](03-deploy.md), then [4](04-shukractl.md) |
| Know why one VM was slow, now or last night | [4](04-shukractl.md), then [9](09-after-the-fact.md) |
| Find out why a VM cannot reach something | [8](08-lost-traffic.md) |
| Be told when something happens | [6](06-watchlist.md) and [7](07-alert-sinks.md) |
| Limit which networks a VM may connect to | [10](10-egress-policy.md) |
| Know if someone is inside a QEMU process | [11](11-vmm-tripwires.md) |

Deeper reference, not a walkthrough: [API](../api.md) · [shukractl](../shukractl.md) · [what each program measures](../signals.md) · [attribution](../attribution.md) · [guest traffic and isolation](../tap.md) · [egress policy](../egress-policy.md) · [learned baselines](../baselines.md) · [responses](../responses.md) · [VMM tripwires](../vmm-tripwires.md) · [where packets die](../drops.md) · [doctor](../doctor.md) · [architecture](../architecture.md) · [testing](../testing.md) · [development](../development.md).
