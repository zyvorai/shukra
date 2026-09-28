# Documentation index

Back to the [README](../README.md).

| Start here | |
|---|---|
| [Run it locally](tutorials/01-run-locally.md) | Build, token, console, fixture mode |
| [Attach traces](tutorials/02-attach-traces.md) | clang, BTF, `make generate`, `-tags shukrabpf` |
| [Deploy a hypervisor](tutorials/03-deploy.md) | `deploy-remote.sh`, systemd, capabilities, TLS, packages |
| [Operator CLI](tutorials/04-shukractl.md) | status, traces, explain, recorder, isolate |
| [Console](tutorials/05-console.md) | Pages, the host banner, isolate |
| [Detection rules](tutorials/06-watchlist.md) | Destinations, ports, thresholds, suppression |
| [Alert sinks](tutorials/07-alert-sinks.md) | Signed webhook, syslog, JSONL file |
| [Find out why traffic is lost](tutorials/08-lost-traffic.md) | Connection outcomes, kernel drops and Explain together |
| [Investigate after the fact](tutorials/09-after-the-fact.md) | A verdict for a past time, who took the CPU, and an incident bundle for a ticket |
| [All tutorials](tutorials/README.md) | The list, in order |

| Reference | |
|---|---|
| [API](api.md) | Every route, parameter and field |
| [shukractl](shukractl.md) | Commands, exit codes, scripting |
| [What each program measures](signals.md) | Signals, caveats, every Prometheus series |
| [Attribution](attribution.md) | Host events versus guest events, and what is not measured |
| [Guest traffic and isolation](tap.md) | The tap program, handshakes, DNS and TLS names, isolate, durability, FluxVM |
| [Where packets die](drops.md) | The drops program |
| [Netlink](netlink.md) | Host link, address, route and neighbor changes |
| [Egress policy](egress-policy.md) | Learn what a VM may connect to, audit it, then enforce it with a timer that reverts it |
| [Responses](responses.md) | Acting on a detection: proposals, approval, and the guardrails |
| [VMM tripwires](vmm-tripwires.md) | What a QEMU process should never do, and what the program that watches for it costs |
| [Learned baselines](baselines.md) | What is new for a VM, with no rule to write |
| [Doctor](doctor.md) | Every check, when it fires, and what to do |
| [Architecture](architecture.md) | How the pieces fit, privileges, kernel requirements |
| [Testing](testing.md) | Every test, where it can run, and what must never run on a live host |
| [Development](development.md) | Build, conventions, adding a program |
| [Tap: what is left](roadmap-taptrace.md) | What is not built yet |
| [Security](../SECURITY.md) | What it reads, what it can do, what a hostile guest can do to it |
| [Changelog](../CHANGELOG.md) | What changed |
| [Product brochure](sales/brochure/Zyvor-Shukra-Product-Brochure.pdf) | Twenty-two pages for a buyer: the scenarios, right-sizing and baselines, the VMM tripwires, egress policy and responses, what each key and party can do, the measured costs, the limits, and a checklist. [Source and claims table](sales/brochure/README.md) |
