# Console

The console is the same API as `shukractl`, drawn for a person who is not going to pipe JSON. It is served by `shukrad` from `-web`, default `web/dist`, on the same port as the API.

## Sign in

Open `http://<hypervisor>:30970`. The password is the API token (`SHUKRA_API_KEY`, or `shukra` when that variable was unset). The token stays in `sessionStorage` under `shukra-token`. Light and dark follow `shukra-theme`.

A wrong token does not open a fixture. Fixture data exists only when you start Vite with `VITE_FIXTURE=1`.

## Pages

| Page | Use it to |
|---|---|
| Overview | Mode, program attach, VM count, detections. Start here. |
| VMs | Name, UUID, runtime label, QEMU PID, tap names from the command line |
| Flight recorder | Replay one VM for a window (60s) |
| Explain | Why a VM looks the way it does, including what is missing |
| KVM | Exit, entry, MMIO, PIO counters, exit handling time, and the reasons that cost the most host time |
| Scheduler | On-CPU time, run-queue delay, and a per-thread table to tell a slow vCPU from a slow iothread |
| Block | Requests, bytes, worst case, p50 and p99, from a log2 histogram (percentiles are computed in userspace) |
| Programs | Attached or detached, and the hook detail |
| Host connections | The QEMU process's TCP connects and sampled retransmits, and, when the tap program is attached, the guest's own connections, connections made to it, UDP flows, and a per-tap table of what became of every connection |
| Drops | What the kernel dropped on each VM tap, by reason, and how much of it was Shukra. Says "not measuring" where the drops program is off, and not a zero |
| Detections | Rule hits: watchlist, port, exec and threshold detections |
| Isolate | The recorded decision |

KVM, Scheduler and Block draw the latency distribution under the table. Hover or focus a bar for its count and share; "Show as table" lists the same numbers. The buckets are powers of two, so a bar's edge can read up to 2x high, and the chart says so. Thread and reason names come from the daemon: exit reasons are named only on Intel hosts.

Hash routes keep you on one origin. The mega-nav is the same set of pages.

## The banner on Host connections

That page keeps a banner: the host connections are QEMU-process connections, not the guest, and `guest_attributed` is false. It is not a warning you dismiss. When the tap program is attached, more tables follow: the guest's own connects, connections made to the guest and UDP flows seen on its tap (each row's `kind` says which, and inbound rows show the peer as the source), and a per-tap table of what became of every connection: attempts, accepted, refused, never answered, blocked, and the handshake time.

## Isolate

The controls are enabled only when the daemon reports it can enforce: the tap program is attached and a management allow list is configured. Otherwise the page says why (for example that no allow list is set) and the buttons stay disabled. Isolate asks for a second confirmation that names what will be cut off, what stays reachable, and what happens if the daemon stops, and the result shown is what the daemon reported: applied, refused, or only partly done. Release lifts it. See [Guest traffic and isolation](../tap.md).

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
