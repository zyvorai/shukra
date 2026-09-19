# Destination watchlist

The watchlist is a userspace check on `tcp_v4_connect`. When the destination matches, Shukra writes a `detection` event. It does not drop the packet, and it does not move the match into BPF.

The connect is still the QEMU process. A hit means that process opened a socket to an address you listed. It does not mean a process inside the guest did. Say that when you page someone.

## File

```yaml
destinations:
  - cidr: 185.0.0.0/8
    severity: high
    name: unexpected-egress
  - cidr: 203.0.113.10
    name: lab-sink
```

| Field | |
|---|---|
| `cidr` | CIDR, or a single IP (treated as `/32` or `/128`) |
| `name` | Shown on the detection |
| `severity` | Optional. Default `high` |

`configs/detections.example.yaml` is the sample. An empty file is an empty list, not an error. A bad CIDR refuses to start the daemon.

## Load it

```bash
shukrad -watchlist /etc/shukra/detections.yaml
```

`deploy-remote.sh` copies the example to `/etc/shukra/detections.yaml` and points the unit at it. Edit that file on the host and restart the unit. There is no reload flag in this build.

```bash
sudo systemctl restart shukra
```

## See a hit

```bash
shukractl security <vm>
shukractl watch --json
```

Or open Detections in the console. The event kind is `detection`. The message is the rule name plus the destination. `guest_attributed` is still false. The flight recorder keeps the same event, so `shukractl recorder <vm> --window 60s` shows it if it happened inside the window.

A connect that matches nothing is a normal `tcp_connect` event, not a detection.

## What you should not add

Do not put "block this CIDR" in the YAML and expect it to happen. Enforcement is the isolate path, and [isolate does not attach](04-shukractl.md). Detection stays a notice until a later slice programs the tap, and even then the allow list for management access has to be explicit. See [roadmap-taptrace.md](../roadmap-taptrace.md).
