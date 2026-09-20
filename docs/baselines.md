# Learned baselines

A watchlist needs someone to know what is bad. A baseline needs no one to know: it learns what each VM **normally** does and reports the first time it does something **new**. A web server that has talked to the same three networks for a month and suddenly talks to a fourth is worth a look, and no rule had to name that network in advance.

It is **off unless the rules file has a `baselines:` section**, because it raises detections of its own. A bare `baselines:` line with nothing under it is not a section (YAML reads it as empty): write `baselines: {}` to turn it on with every default.

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

All of it comes from what the VM's own tap sees (see [what the tap records](tap.md#what-it-records)), so it is `guest_attributed`. Nothing is learned from a host connect, which belongs to QEMU and not the guest. A baseline belongs to a VM's **name**: a renamed VM starts a new one.

| Kind | The item | Learned from | Reported as |
|---|---|---|---|
| `destination` | The **network** the guest connected or sent to: the /24 of an IPv4 address, the /64 of an IPv6 address | `guest_connect` and `guest_flow` | `new-destination`, medium |
| `dns-suffix` | The **site** of a name it looked up: `www.api.example.com` is `example.com`, `shop.example.co.uk` is `example.co.uk` | `guest_dns`, and `guest_tls` when it has a name | `new-dns-suffix`, low |
| `inbound-peer` | The **network** that connected in to it | `guest_inbound` | `new-inbound-peer`, medium |

What the guest *attempted* is what is learned, whether or not it worked: a connection that was refused, that nobody answered, or that isolation or an enforcing [egress policy](egress-policy.md) dropped still teaches its network. A baseline therefore records where a VM tries to go, not only where it succeeds.

A whole network and a whole site, not an address and a host: a service that moves between neighbouring addresses, a client that lands on another member of a pool, or a site with a new subdomain is not new each time. Reverse lookups (`…in-addr.arpa`, `…ip6.arpa`) all collapse into one item, because every address has a different one and they say nothing about what the guest is doing. A name that was cut short (`dns_truncated`) is not a site and is skipped.

The registrable part of a name uses a **short built-in list** of two-label public suffixes (63 in all, among them `co.uk`, `com.au` and `co.jp`). For a suffix that is not in it the name is learned one label too wide (`foo.example.co.xx` is `co.xx`), which makes it quieter and never louder. There is no dependency on the full public suffix list.

## The learning period

A VM is **only observed** for `learn` from the first time Shukra sees it do something: its baseline is created by its first guest event, so a VM that has sent and received nothing has no baseline yet, and `shukractl baseline` says `no VM has been observed yet` if none has. During the period everything is recorded and nothing is reported. After that the first sighting of an item is reported **once**, as a detection, and recorded, so it is never new again. A VM first seen later has its own learning period, so a new VM does not alarm for its first day. The start of learning is stored, so a restart does not begin it again.

The end of a VM's period is worked out as *first seen + `learn`* every time, so changing `learn` and reloading moves every VM's end with it: shortening it ends learning sooner, and lengthening it puts a VM that had finished back into learning until the new end.

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
[low]    new-dns-suffix   web-01 connected to badsite.test for the first time (TLS server name c2.badsite.test, port 443)
```

It carries the tap and the VM like any guest detection and goes to every alert sink. A [response](responses.md) can answer it by name (`rules: [new-destination]`), though a first sighting is a poor reason to isolate a VM and `propose` is the sensible mode.

## What a guest can do to it

A guest controls the addresses it talks to and the names it asks for, so the baseline is bounded against it:

- **Its sets have a fixed size** (`max_items` per kind, 2048 by default). A guest that invents endless names or networks can only turn its own sets over: the item unseen for longest is dropped, and it can never make the daemon's memory grow.
- **A daily cap** (`max_alerts_per_day`, 20 by default) bounds how much one VM can raise. Past it, new items are still learned, counted (`shukra_baseline_suppressed_total`) and **not reported**, and one `baseline-cap` detection says so, once a day. A guest that floods new names to bury one that matters is therefore visible as a cap being hit.
- **A guest can hide inside its own learning period**: whatever it does in the first `learn` is what becomes normal. Start a VM you do not trust under a watchlist (`destinations`, `dns`), not a baseline.

## How do I know it works

```bash
shukractl baseline                  # BASELINE  learning period 24h0m0s ...  and one line per VM
shukractl baseline web-01 --items   # what web-01 has learned, most recently seen first (at most 500)
```

- **It is on.** `BASELINE  off: the rules file has no baselines section` means it is not. `WARNING: not kept across a restart (no -data-dir)` means it is on and will start over with every restart.
- **It is learning.** Each VM has a line with `learning until <time>` and counts per kind that grow while the VM is used. A VM with no line has not produced a guest event: check `shukractl trace tap` and `shukractl doctor` (`blind-vms`).
- **It reports.** To see it without waiting a day, on a test host set `learn: 1m` (the shortest allowed), reload, use a VM for a minute, then from inside it connect to a network it has not used, and look for a detection:

```yaml
baselines:
  learn: 1m
```

```bash
shukractl security web-01           # [medium] new-destination ... contacted 203.0.113.0/24 for the first time
```

Doing the same again raises nothing: the item is known now. `shukractl baseline web-01 --forget` and a new minute start it again, and records a `baseline-forgotten` detection.
- **It is kept.** With `-data-dir`, `baselines.json` exists (it is written once a minute and when the daemon stops cleanly, so a crash can lose up to a minute of learning), and after a restart `learning until` has not moved.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `BASELINE  off: the rules file has no baselines section` | The section is absent, or is a bare `baselines:` with nothing under it | Add `baselines: {}` (or the keys you want), `shukractl rules check`, `systemctl reload shukra` |
| A VM is missing from `shukractl baseline` | It has produced no guest event: idle, or no tap Shukra is on | `shukractl trace tap --vm <vm>`; doctor `blind-vms`, `vm-tap-other-netns` |
| Nothing is ever reported for a VM | It is still learning; or `kinds` leaves the kind out; or it hit the daily cap (`held back in all` above 0); or the daemon restarts more often than `learn` and nothing is kept | The `learning until` time; doctor `baselines`; `-data-dir` |
| A `baseline-cap` detection | The VM used its `max_alerts_per_day`; further new items are learned and counted (`shukra_baseline_suppressed_total`) but not reported until the day rolls over | Look at `shukractl baseline <vm> --items` for what was held back, and decide whether the cap or the VM is wrong |
| Too many `new-destination` for a VM that talks to a large pool | Pools spread across many /24s | Lengthen `learn`, drop `destination` from `kinds` for now, and let the cap bound it. A watchlist rule is the better tool for a known-bad network |
| An old destination is reported as new again | It was not seen for `max_age` (30 days by default) and was forgotten | Raise `max_age`, or accept it |
| Everything is new after a restart | No `-data-dir`, or `baselines.json` could not be read (the log says `learning starts over`) | Fix the directory. A damaged file costs the learning, never the daemon |
| `baseline --forget` says `no baseline is kept for that VM` (404) | The daemon has not seen that name | The name as `shukractl vms` prints it |
| `baseline --forget` says `baselines are not on` (409) | No `baselines:` section | Add one |
| A file that fails `rules check` with `baselines: ...` | A value is out of range (table below) | The message names the key and the range |

## Limits

| Key | Range | Default |
|---|---|---|
| `learn` | 1 minute to 90 days | 24h |
| `max_alerts_per_day` | 1 to 1,000, per VM | 20 |
| `max_items` | 16 to 100,000, per VM per kind | 2,048 |
| `max_age` | At least `learn` | 720h (30 days) |
| `kinds` | `destination`, `dns-suffix`, `inbound-peer`, each at most once | all three |
| `severity` | A map from a kind to `low`, `medium`, `high` or `critical` | destination medium, dns-suffix low, inbound-peer medium |

Also: `shukractl baseline <vm> --items` and `GET /api/v1/baseline?vm=&items=1` return the 500 most recently seen items; an unseen item is dropped at `max_age` (checked once a minute) or, when a set is full, the one unseen longest; the "day" of the cap is a block of 24 hours that starts when the VM is first seen, and each later block starts at the first new item after the last one ended.

## Forgetting

`shukractl baseline web-01 --forget` (admin key only) drops what a VM has learned and starts its learning period again, which is right after a deliberate change of what the VM does. It is also a way to hide a change, so it is **recorded as a `baseline-forgotten` detection** naming who did it.

Items not seen for `max_age` (30 days) are forgotten, and are new again if they return.

## What it does not do

- **It does not say a new thing is bad.** New is the only claim. A person decides, which is why the severities are medium and low.
- **It learns whatever the VM does**, including what it should not. It is not a substitute for a watchlist of what you know is wrong.
- **It sees only what the tap sees**: not a VM whose interface Shukra cannot attach to (`shukractl doctor` names those), and not the process inside the guest that did it. Exec names are not learned: the built-in unexpected-exec check already reports every process the VMM starts that is not on its allow list.
- **A name it did not see.** DNS over TCP, TLS or HTTPS is not read, so a site reached that way is learned only as a destination.

## Where it is

`shukractl baseline`, `GET /api/v1/baseline` (`?vm=web-01&items=1` for the items; `learn` and `maxAlertsPerDay` are at the top), `POST /api/v1/baseline/forget`, and `/metrics`: `shukra_baseline_learning{vm}`, `shukra_baseline_items{vm,kind}`, `shukra_baseline_new_total{vm}` and `shukra_baseline_suppressed_total{vm}` (present only while the section is on). What is learned is kept in `baselines.json` under `-data-dir`, mode 0600: it lists the networks and names each VM talks to, so treat it like the event list.

## From a baseline to a policy

What a VM's baseline holds as `destination` is what an [egress policy](egress-policy.md) can be proposed from: `shukractl policy learn <vm>` lists those networks, `policy apply <vm> --mode audit --from-baseline` puts the VM under them in audit mode, and nothing is dropped until a person enforces it. A VM still inside its learning period gets a proposal that says so, because what it has not done yet is not on it.

See also: [what the tap records](tap.md#what-it-records), which is where every learned item comes from. [Egress policy](egress-policy.md), which holds a VM to what it has learned. [Responses](responses.md), which can propose isolating a VM on a detection. [Doctor](doctor.md), for the `baselines` check. [Detection rules](tutorials/06-watchlist.md), for `suppress` and the rest of the rules file.
