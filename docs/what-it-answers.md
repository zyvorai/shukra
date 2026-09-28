# What it answers

Back to the [README](../README.md).

| The question | Ask | Guide |
|---|---|---|
| Why is this VM slow right now? | `shukractl explain <vm>`: ranked host-side causes over the last minute, with evidence and a list of what Shukra cannot see | [Tutorial 4](tutorials/04-shukractl.md) |
| Why *was* it slow at 03:12, hours ago? | `shukractl explain <vm> --at 2026-09-20T03:12:00Z`, and `shukractl incident <vm> --at -3h --out bundle.json` | [Tutorial 9](tutorials/09-after-the-fact.md) |
| Is the host, the disk or a noisy neighbour to blame? | `trace kvm`, `trace sched`, `trace block`: exit handling time, run-queue delay per vCPU thread, block latency histograms | [Signals](signals.md) |
| Which VM is the noisy neighbour? | `trace contention`, and `explain` (`noisy_neighbour`, `cpu_preempted`) | [Signals](signals.md#vcpu-preemption) |
| Is each VM the right size? | `shukractl advise` | [Signals](signals.md#right-sizing) |
| What is new for this VM? | `shukractl baseline` | [Learned baselines](baselines.md) |
| What is this VM connecting to, who connects to it, and what names does it look up or ask for? | `guest_connect`, `guest_flow`, `guest_inbound`, `guest_dns`, `guest_tls` events (`shukractl watch`, the Host connections page) | [Guest traffic](tap.md) |
| Did the connection get an answer? | `trace tap`: accepted, refused, never answered or blocked, with the handshake time | [Lost traffic](tutorials/08-lost-traffic.md) |
| Is something dropping this VM's traffic, or is it Shukra? | `trace drops` and `doctor` | [Where packets die](drops.md) |
| Did the host's own network change under the VM? | `netlink_*` on `shukractl watch`; `tap-link-down`, `default-route-removed` and the other Netlink detections | [Netlink](netlink.md) |
| Is a guest not reading its NIC? | `doctor` (`vm-nic-not-consumed`) and `explain` (`guest_not_reading_nic`) | [Doctor](doctor.md) |
| Where may this VM connect to? | `shukractl policy` | [Egress policy](egress-policy.md) |
| Is a VMM doing something a VMM never does? | Nothing to run: `vmm-sensitive-open` and `vmm-syscall` detections | [VMM tripwires](vmm-tripwires.md) |
| Can it act on a detection, safely? | `responses:` in the rules file, `shukractl actions`, `approve`, `reject` | [Responses](responses.md) |
| Can I cut a compromised VM off without touching it? | `shukractl isolate <vm>` | [Guest traffic and isolation](tap.md#isolate) |
| Is Shukra itself set up safely? | `shukractl doctor`: exposure, what is attached, what it cannot see, each with a fix | [Doctor](doctor.md) |
