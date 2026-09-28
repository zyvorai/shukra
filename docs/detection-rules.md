# Detection rules

Back to the [README](../README.md).

One YAML file (`-watchlist`), re-read on `systemctl reload shukra`, validated with `shukractl rules check`. A bad file keeps the previous rules.

```yaml
destinations:                    # a watched network: a connect out to it, or a connection in from it
  - {cidr: 185.0.0.0/8, name: unexpected-egress, severity: high}
ports:
  - {port: 25, name: smtp-egress}                    # a connect the VM made (the default)
  - {port: 53, name: dns-out, proto: udp}            # tcp (default), udp or any
  - {port: 22, name: ssh-into-vm, dir: in}           # a connection made TO the VM
dns:                             # a name the guest looked up (UDP port 53): suffix, exact or contains
  - {name: crypto-pool, suffix: nanopool.org, severity: high}
tls:                             # a server name in a TLS ClientHello, matched the same way
  - {name: tor-front, suffix: torproject.org, severity: medium}
thresholds:                      # a per-VM metric over a window
  - {name: vm-traffic-dropped, metric: guest_drops_per_sec, value: 5, window: 30s}
  - {name: slow-disk, metric: block_write_p99_ms, value: 50}
exec_allow: [node_exporter]
baselines:                       # off unless present: what is new for each VM after it has been learned
  learn: 24h
vmm:                             # optional: the tripwires already work with no section
  ignore: [/root/images]
responses:                       # off unless present: propose isolating a VM, which a person approves
  - {name: contain-miners, rules: [crypto-pool], action: isolate, mode: propose}
guardrails:
  never_isolate: [db-primary]
suppress: 5m
```

A detection keeps the attribution of the event that caused it, so a rule that fires on something the guest did says the guest did it. Threshold metrics: `block_read_p99_ms`, `block_write_p99_ms`, `block_read_bytes_per_sec`, `block_write_bytes_per_sec`, `block_iops`, `wakeup_delay_ms`, `runqueue_delay_p99_ms`, `vcpu_preempted_ms_per_sec`, `kvm_exit_latency_p99_ms`, `kvm_exits_per_sec`, `tcp_retransmits_per_sec`, and, from the guest's tap, `guest_drops_per_sec`, `guest_connect_refused_per_sec`, `guest_connect_timeouts_per_sec` and `guest_inbound_per_sec`. A rule says nothing until a full window of history exists, and nothing for a VM whose measurement is not on.

See [Detection rules](tutorials/06-watchlist.md), [Alert sinks](tutorials/07-alert-sinks.md) (signed webhook, syslog, JSONL file), [Learned baselines](baselines.md), [VMM tripwires](vmm-tripwires.md) and [Responses](responses.md) for each section.
