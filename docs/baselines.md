# Learned baselines

A watchlist needs someone to know what is bad. A baseline needs no one to know: it learns what each VM **normally** does and reports the first time it does something **new**. A web server that has talked to the same three networks for a month and suddenly talks to a fourth is worth a look, and no rule had to name that network in advance.

It is **off unless the rules file has a `baselines:` section**, because it raises detections of its own.

```yaml
baselines:
  learn: 24h                 # how long each VM is only observed. Default 24h
  max_alerts_per_day: 20     # per VM. Default 20
  kinds: [destination, dns-suffix, inbound-peer]   # default all three
  severity: {dns-suffix: low}                     # defaults: destination medium, dns-suffix low, inbound-peer medium
  # max_items: 2048          # per VM per kind. Default 2048
  # max_age: 720h            # how long an unseen item is remembered. Default 30 days
```

`systemctl reload shukra` applies it. Start the daemon with `-data-dir` (the shipped unit does): without it, learning starts over with every restart, and a daemon that restarts more often than the learning period would never report anything. `shukractl doctor` warns about exactly that (`baselines`).

## What is learned

All of it comes from what the VM's own tap sees, so it is `guest_attributed`. Nothing is learned from a host connect, which belongs to QEMU and not the guest.

| Kind | The item | Learned from | Reported as |
|---|---|---|---|
| `destination` | The **network** the guest connected or sent to: the /24 of an IPv4 address, the /64 of an IPv6 address | `guest_connect` and `guest_flow` | `new-destination`, medium |
| `dns-suffix` | The **site** of a name it looked up: `www.api.example.com` is `example.com`, `shop.example.co.uk` is `example.co.uk` | `guest_dns`, and `guest_tls` when it has a name | `new-dns-suffix`, low |
| `inbound-peer` | The **network** that connected in to it | `guest_inbound` | `new-inbound-peer`, medium |

A whole network and a whole site, not an address and a host: a service that moves between neighbouring addresses, a client that lands on another member of a pool, or a site with a new subdomain is not new each time. Reverse lookups (`…in-addr.arpa`, `…ip6.arpa`) all collapse into one item, because every address has a different one and they say nothing about what the guest is doing. A name that was cut short (`dns_truncated`) is not a site and is skipped.

The registrable part of a name uses a **short built-in list** of two-label public suffixes (63 in all, among them `co.uk`, `com.au` and `co.jp`). For a suffix that is not in it the name is learned one label too wide (`foo.example.co.xx` is `co.xx`), which makes it quieter and never louder. There is no dependency on the full public suffix list.

## The learning period

A VM is **only observed** for `learn` from the first time Shukra sees it: everything is recorded and nothing is reported. After that the first sighting of an item is reported **once**, as a detection, and recorded, so it is never new again. A VM first seen later has its own learning period, so a new VM does not alarm for its first day. The start of learning is stored, so a restart does not begin it again.

`shukractl baseline` says where each VM stands:

```text
BASELINE  learning period 24h0m0s, at most 20 new-item alerts per VM per day
  vm=web-01  learning until 2026-09-21T03:00:00Z  (destination 4, dns-suffix 2, inbound-peer 0)  new alerts today 0, held back in all 0
  vm=db-01  reporting  (destination 9, dns-suffix 1, inbound-peer 1)  new alerts today 3, held back in all 5
```

`shukractl baseline web-01 --items` lists what it has learned, most recently seen first, with when each was first and last seen.

## What a detection says

```text
[medium] new-destination  web-01 contacted 192.0.2.0/24 for the first time (tcp to 192.0.2.44:22)
[low]    new-dns-suffix   web-01 looked up badsite.test for the first time (c2.badsite.test, A)
[medium] new-inbound-peer web-01 was connected to from 203.0.113.0/24 for the first time (203.0.113.8, to port 3389)
```

It carries the tap and the VM like any guest detection, goes to every alert sink, and is held back as a repeat by `suppress` like the others.

## What a guest can do to it

A guest controls the addresses it talks to and the names it asks for, so the baseline is bounded against it:

- **Its sets have a fixed size** (`max_items` per kind, 2048 by default). A guest that invents endless names or networks can only turn its own sets over: the item unseen for longest is dropped, and it can never make the daemon's memory grow.
- **A daily cap** (`max_alerts_per_day`, 20 by default) bounds how much one VM can raise. Past it, new items are still learned, counted (`shukra_baseline_suppressed_total`) and **not reported**, and one `baseline-cap` detection says so, once a day. A guest that floods new names to bury one that matters is therefore visible as a cap being hit.
- **A guest can hide inside its own learning period**: whatever it does in the first `learn` is what becomes normal. Start a VM you do not trust under a watchlist (`destinations`, `dns`), not a baseline.

## Forgetting

`shukractl baseline web-01 --forget` (admin key only) drops what a VM has learned and starts its learning period again, which is right after a deliberate change of what the VM does. It is also a way to hide a change, so it is **recorded as a `baseline-forgotten` detection** naming who did it.

Items not seen for `max_age` (30 days) are forgotten, and are new again if they return.

## What it does not do

- **It does not say a new thing is bad.** New is the only claim. A person decides, which is why the severities are medium and low.
- **It learns whatever the VM does**, including what it should not. It is not a substitute for a watchlist of what you know is wrong.
- **It sees only what the tap sees**: not a VM whose interface Shukra cannot attach to (`shukractl doctor` names those), and not the process inside the guest that did it. Exec names are not learned: the built-in unexpected-exec check already reports every process the VMM starts that is not on its allow list.
- **A name it did not see.** DNS over TCP, TLS or HTTPS is not read, so a site reached that way is learned only as a destination.

## Where it is

`shukractl baseline`, `GET /api/v1/baseline` (`?vm=web-01&items=1` for the items), `POST /api/v1/baseline/forget`, and `/metrics`: `shukra_baseline_learning{vm}`, `shukra_baseline_items{vm,kind}`, `shukra_baseline_new_total{vm}` and `shukra_baseline_suppressed_total{vm}` (present only while the section is on). What is learned is kept in `baselines.json` under `-data-dir`, mode 0600: it lists the networks and names each VM talks to, so treat it like the event list.
