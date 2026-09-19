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
| KVM | Exit, entry, MMIO, PIO counters |
| Scheduler | On-CPU and wakeup delay |
| Block | Log2 histogram, p50 and p99 in the page, not in the kernel |
| Programs | Attached or detached, and the hook detail |
| Host connections | TCP connects and sampled retransmits |
| Detections | Watchlist hits |
| Isolate | The recorded decision |

Hash routes keep you on one origin. The mega-nav is the same set of pages.

## The banner on Host connections

That page keeps a banner: these are QEMU-process connections, not the guest, and `guest_attributed` is false. It is not a warning you dismiss. Tap names on the VM page are identity, not a packet trace. If a connect looks like "the VM talked to the internet," re-read the banner and [attribution](../attribution.md).

## Isolate

The Apply control stays disabled. The page states that isolate is not attached. Recording a decision in the API does not program a NIC. When a later build attaches TC or TCX, this page is where that state will change, and it will have to say so in the response, not only in the button.

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
