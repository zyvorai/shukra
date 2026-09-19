# Tutorials

Short paths through Shukra. Each one assumes you have read the boundary: Shukra observes the hypervisor from outside, and never runs anything inside a guest. It attributes traffic to a VM only when it is seen on that VM's own tap, and it can isolate a VM only when you give it a management allow list.

1. [Run it locally](01-run-locally.md) — build the binaries and open the console without attaching BPF.
2. [Attach traces](02-attach-traces.md) — compile CO-RE objects on a Linux host with BTF and start `shukrad` as root.
3. [Deploy a hypervisor](03-deploy.md) — rsync, remote build, systemd, and the checks that mean it worked.
4. [Operator CLI](04-shukractl.md) — the daily commands, JSON, and the isolate record.
5. [Console](05-console.md) — what each page is for, and the banner you should not click past.
6. [Detection rules](06-watchlist.md) — destinations, ports, exec allow-list, per-VM thresholds, and suppression.
7. [Alert sinks](07-alert-sinks.md) — webhook (signed), syslog and file delivery.
8. [Find out why a VM's traffic is lost](08-lost-traffic.md) — connection outcomes, kernel drops and Explain together: is the destination refusing, is something on the host dropping, or is the guest not reading its NIC.

Deeper reference, not a walkthrough: [API](../api.md) · [shukractl](../shukractl.md) · [what each program measures](../signals.md) · [attribution](../attribution.md) · [guest traffic and isolation](../tap.md) · [where packets die](../drops.md) · [architecture](../architecture.md) · [testing](../testing.md) · [development](../development.md).
