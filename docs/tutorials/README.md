# Tutorials

Short paths through Shukra. Each one assumes you have read the boundary: this release observes the hypervisor. It does not attribute packets to a guest, and isolate does not enforce.

1. [Run it locally](01-run-locally.md) — build the binaries and open the console without attaching BPF.
2. [Attach traces](02-attach-traces.md) — compile CO-RE objects on a Linux host with BTF and start `shukrad` as root.
3. [Deploy a hypervisor](03-deploy.md) — rsync, remote build, systemd, and the checks that mean it worked.
4. [Operator CLI](04-shukractl.md) — the daily commands, JSON, and the isolate record.
5. [Console](05-console.md) — what each page is for, and the banner you should not click past.
6. [Destination watchlist](06-watchlist.md) — notice a QEMU-process connect to a CIDR you care about.

Deeper reference, not a walkthrough: [shukractl](../shukractl.md), [attribution](../attribution.md), [tap/TCX roadmap](../roadmap-taptrace.md).
