# Console

The console is the same API as `shukractl`, drawn for a person who is not going to pipe JSON. It is served by `shukrad` from `-web`, default `web/dist`, on the same port as the API.

## Sign in

Open `http://127.0.0.1:30970` on the hypervisor (the unit does not listen on other addresses). Enter the API token. That token (`SHUKRA_API_KEY` from `/etc/shukra/env` on a packaged install, or `shukra` only when you started the binary yourself with the variable unset) is the only credential. There is no username. The console keeps the token in memory for that page load only, so a reload, or the log-out button, asks for it again, and nothing secret is left in the browser's storage. Light and dark follow `shukra-theme`.

A wrong token does not open a fixture. It says `The API token was rejected.`, or `Could not reach shukrad. Check the URL and try again.` when the daemon does not answer. Fixture data exists only when you start Vite with `VITE_FIXTURE=1`.

You should land on **Overview**: the number of VMs, `8/8` programs attached on a Linux host with BPF (`0/8` on a laptop build), the detection count, and the mode `observe`. It refreshes every five seconds and pauses while the tab is hidden.

The page itself (`/` and its scripts) is served without a key. Every number on it comes from the API with your token, so the console shows nothing the CLI could not.

## Pages

There are seventeen: Overview, and four menus in the top bar. **Investigate** has VMs, Flight recorder and Explain. **Diagnostics** has KVM, Scheduler, Contention, Right-size, Block, Memory and Programs. **Network** has Host connections and Drops. **Security** has Detections, Actions, Egress policy and Isolate.

| Page | Use it to |
|---|---|
| Overview | Mode, program attach, VM count, detections. Start here |
| VMs | Name, UUID, runtime label (`qemu`, `libvirt`, `kubevirt`, `fluxvm`), the VMM's PID, and the interface Shukra traces (`taps`) |
| Flight recorder | Replay one VM for the last 60 seconds, or the full ring |
| Explain | Why a VM looks the way it does, including what is missing. Live, or at a past time (below) |
| KVM | Exit, entry, MMIO, PIO counters, exit handling time, and the reasons that cost the most host time |
| Scheduler | On-CPU time, run-queue delay, **vCPU preemption** (how long the vCPUs were runnable but off a host CPU, and who had it), and a per-thread table to tell a slow vCPU from a slow iothread |
| Contention | Which VM took whose CPU: pairs of victim and culprit, each VM's preemption split into other VMs, its own threads and host tasks, and what each culprit VM was doing meanwhile |
| Right-size | Each VM's vCPUs, how much of the window they were halted and busy and preempted, and the advice (over-provisioned, starved, fine) with its evidence and how sure it is, most urgent first |
| Block | Service time and queue time, requests, bytes, errors, worst case, p50 and p99. Percentiles are computed in userspace |
| Memory | Direct reclaim stalls and OOM kills of the VMM process. Not the guest's own memory |
| Programs | Attached or detached, and the hook detail, for all eight programs: `kvm`, `sched`, `block`, `mem`, `net`, `vmm`, `drops` and `tap` |
| Host connections | The QEMU process's TCP connects and sampled retransmits, and, when the tap program is attached, the guest's own connections, connections made to it, UDP flows, the names it looked up, and a per-tap table of what became of every connection |
| Drops | What the kernel dropped on each VM tap, by reason, and how much of it was Shukra. Says "not measuring" where the drops program is off, and not a zero |
| Detections | Every detection: watchlist, port, DNS and TLS names, exec, thresholds, baseline first sightings, egress-policy strays and changes, VMM tripwires, and what responses announced. Read-only: each row is the severity, the destination if it has one, and the message |
| Actions | Proposed isolations waiting for a decision, with Approve and Reject (a confirmation names the VM and the consequence), and what responses did: executed, refused by a guardrail, lapsed, released. Says `Responses are off` until the rules file has a `responses:` section |
| Egress policy | Which networks each VM may start connections to: mode, how many networks, who set it, the kernel's mode and counters per tap, and any policy waiting to be confirmed, listed first, with **Confirm** and **Remove** buttons. An orphan (a tap enforcing a policy nobody has a record of) is shown with a **Remove it** button. Proposing and applying a policy is `shukractl policy`, not this page |
| Isolate | Cut a VM off except the management network, and lift it again. The controls are enabled only when the daemon can enforce |

KVM, Scheduler and Block draw the latency distribution under the table. Hover or focus a bar for its count and share; "Show as table" lists the same numbers. The buckets are powers of two, so a bar's edge can read up to 2x high, and the chart says so. Thread and reason names come from the daemon: exit reasons are named only on Intel hosts.

Hash routes keep you on one origin: `#page=policy`, `#page=actions`, `#page=explain` and so on open a page directly, so you can link a colleague to one (they still sign in). The mega-nav is the same set of pages. An unknown route opens Overview.

## The banner on Host connections

That page keeps a banner: the host connections are QEMU-process connections, not the guest, and `guest_attributed` is false. It is not a warning you dismiss. When the tap program is attached, more tables follow: the guest's own connects, connections made to the guest and UDP flows seen on its tap (each row's `kind` says which, and inbound rows show the peer as the source), the names the guest looked up (one row per name and type, once a minute), and a per-tap table of what became of every connection: attempts, accepted, refused, never answered, blocked, and the handshake time.

## Explain at a past time

The Explain page has an **At** field. Left blank it is the live verdict, refreshed every few seconds. Set to a date and time (your browser's zone) it asks the daemon for the verdict at that time from the stored snapshots, with a look-back of 15 minutes, an hour or 6 hours; it says what it stood on and how coarse that is, or that nothing is stored. **Back to now** clears it. **Download incident bundle** saves the verdict, the window's detections, the recorder's events and the VM's isolate requests as one JSON file; it names VMs, addresses and DNS names, so treat it like the event list.

## VM fields

Explain, Flight recorder and Isolate each have a VM field. It opens on the first VM the daemon knows and suggests the others as you type. If the daemon knows no VM the field is empty; it never opens on a made-up name.

## Filtering the connection tables

Host connections, guest connections and DNS names are lists of recent events, and on a busy host (k3s, cilium) the host list alone is hundreds of rows. Each table is **newest first**, shows **50 rows**, and says how many there are in all (`Host connections (247)`, `Showing the newest 50 of 247.`) with a button to show 50 more. Nothing is cut off silently.

Two controls above the tables narrow all of them at once:

- **Show**: everything, **host processes (no VM)** (the connects made by k3s, cilium and other host software, which belong to no VM), or one VM. Choosing a VM also narrows the per-tap table to that VM's tap, and choosing host processes empties it, since a host process has no tap.
- **Search**: text matched, ignoring case, against the address, port, DNS name, query type, protocol, kind and attribution.

An empty result says `Nothing matches this filter.`, which is different from `None seen yet.`. The filter is in your browser: it works on the events the daemon holds: 2048 in all, with a share reserved for each kind (guest events, host connects, detections and so on), so a flood of host connects cannot push a guest's events out. A busy kind is still trimmed to its share when the list is full, so the oldest host connects are the ones that go.

## Isolate

The controls are enabled only when the daemon reports it can enforce: the tap program is attached and a management allow list is configured (`-isolate-allow`). Otherwise the page says why (for example that no allow list is set) and the buttons stay disabled. Turning that flag on lets whoever holds the admin key cut a VM off, so give the host a real key and TLS first ([tutorial 10, step 5](10-egress-policy.md#5-give-enforcement-its-floor-the-management-allow-list)). Isolate asks for a second confirmation that names what will be cut off, what stays reachable, and what happens if the daemon stops, and the result shown is what the daemon reported: applied, refused, or only partly done. Release lifts it. See [Guest traffic and isolation](../tap.md).

## Egress policy and Actions

These two pages are where a person decides. Neither changes anything until you click, and both say what a click will do.

**Egress policy** lists every VM under a policy, with a headline like `2 VMs under a policy, 1 waiting to be confirmed`. A policy that is enforcing and waiting shows `unconfirmed: goes back to audit with 12 networks at <time>` in the mode column and sorts first. **Confirm** keeps it. **Remove…** asks first, and says the VM may connect anywhere again. If the daemon has no `-data-dir`, the page says enforcing is not possible and only audit is. Applying a policy is on the command line: [learn, audit, enforce](10-egress-policy.md).

**Actions** lists what a response proposed. **Approve…** asks first with a sentence that names the VM, the response and the rule, and says its tap will drop everything except ARP, IPv6 neighbour discovery and the management networks until it is released, and only then isolates it. **Reject** does nothing to the VM. A proposal that nobody decides lapses. The evidence a proposal was made on is `shukractl actions --bundle <id>`. See [responses](../responses.md).

## Develop against it

```bash
cd web
npm run dev
```

Vite listens on `5173` and proxies `/api` to `127.0.0.1:30970`. Start `shukrad` first, or use `VITE_FIXTURE=1` and do not confuse the two.

Production build:

```bash
npm --prefix web ci
npm --prefix web run build
```

`shukrad` will not serve a path that escapes `-web`. A missing `index.html` means you built the API and not the console. `make web` is the usual fix.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | A blank page, or the API's JSON, at `/` | The daemon has no console: `-web` points at a directory with no `index.html`. `make web` |
> | `The API token was rejected.` | The password field is the API token. On a deployed host: `sudo grep SHUKRA_API_KEY /etc/shukra/env` |
> | `Could not reach shukrad.` | Wrong host or port, a firewall on `30970`, or `https://` against a daemon serving plain HTTP (or the reverse) |
> | Signed out after every reload | Expected: the token is kept in memory only |
> | `The daemon rejected the API token.` after signing in | The key changed under you. The daemon was restarted with another `SHUKRA_API_KEY` |
> | Guest tables on Host connections are empty | The tap program is not attached to that VM. Programs page, and `shukractl doctor` |
> | Egress policy, Actions or baselines say they are off | The rules file has no `baselines:` or `responses:` section, or no policy has been applied yet. Not a fault |
> | Isolate is greyed out | Its own text says why, usually no `-isolate-allow`. Set one only after the host has a real key and TLS (see above) |
> | A page keeps showing old data | Live pages refresh every five seconds, and not while the tab is hidden. Explain at a past time is fetched once |
