# Next slice: taptrace

Host `tcp_v4_connect` cannot name the guest that sent a packet. The QEMU process is the socket owner.

The next slice attaches TC or TCX on each VM tap or vhost interface discovered from the QEMU command line (`ifname=tapN` today). That is the first place a packet can be attributed to a VM rather than to QEMU.

```text
tap0  VM payment-prod-03
tap1  VM api-01
        |
      TC/TCX
        |
     shukrad
```

Enforcement stays in userspace. `shukractl isolate` already records the decision and refuses to attach a program. A later build may program the tap only after that decision, and it must keep management access on an explicit allow list. Detection does not move entirely into BPF.

Until that slice ships, the console and `shukractl trace net` keep the host-only banner.
