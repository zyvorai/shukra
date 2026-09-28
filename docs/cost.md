# What it costs

Back to the [README](../README.md).

Measured figures, each from the page that shows how it was taken. The first three were measured on the reference hypervisor (Intel Xeon E-2336, Linux 6.8), the daemon's on a 12-core production node running k3s and Cilium. Scale them by your own rates.

| What | Cost | Source |
|---|---|---|
| `vmm` program | about **183 ns** per `openat`, **0.161% of one core** at about 8,100 tracepoint hits a second; about 2% of a core at 100,000 opens a second. `-vmm-tripwires=false` if a host is that busy | [VMM tripwires](vmm-tripwires.md#what-it-costs) |
| TLS server names in the `tap` program | about 10 to 15 ns added to a data segment, nothing to an ACK or a UDP datagram, about 60 to 85 ns for the one segment per connection that is a hello | [Guest traffic](tap.md#what-it-costs) |
| Egress policy in the `tap` program | with no policy on a tap, one extra read and compare per packet: about 7 to 10 ns, about 1% of a core at a million packets a second | [Egress policy](egress-policy.md#cost) |
| The daemon | after the daemon-cost fixes, 5 to 9% of a core and about 88 MB on a 12-core, 10-VM node, down from about 55% and 155 MB, with the same output | [Changelog](../CHANGELOG.md) |

The cost of the other programs is in [What each program measures](signals.md).
