"""The brochure's diagrams, drawn in code so they stay editable and consistent."""
from svg import *


def cw(w, size=10.5):
    """Approximate characters that fit a card body of width w at font size `size`."""
    return max(8, int((w - 24) / (size * 0.53)))


# ---------------------------------------------------------------- 1. how eBPF works
def ebpf_pipeline():
    o = []
    o.append(rect(258, 12, 452, 208, WARM, LINE, 1.2, 14, "5 4"))
    o.append(text(272, 32, "HYPERVISOR KERNEL", 10, 700, DEEP, spacing=1.2))
    boxes = [
        (8, 55, 108, 84, "1  Program source", "one small C file per program: bpf/*.bpf.c", GREY, LINE),
        (134, 55, 108, 84, "2  clang + CO-RE", "compiled against the kernel's BTF, loaded by bpf2go", GREY, LINE),
        (274, 46, 150, 102, "3  Verifier", "proves the program ends, stays in bounds and reads only allowed memory. An unsafe program is refused, never run", PALE, SIG),
        (440, 55, 84, 84, "4  JIT", "native machine code", GREY, LINE),
        (540, 46, 160, 102, "5  Hook", "attached where the kernel already has one: tracepoint, kprobe, TCX on a VM tap", PALE, SIG),
    ]
    for x, y, w, h, t, b, f, s in boxes:
        o.append(card(x, y, w, h, t, b, cw(w, 9.5), f, s, size=9.5, tsize=11.5))
    for x1, x2 in [(116, 134), (242, 274), (424, 440), (524, 540)]:
        o.append(line(x1, 97, x2, 97, SOFT, 1.6, None, True))
    o.append(card(380, 168, 320, 42, "Maps and one small ring buffer", "", 40, "#fff", SIG, tsize=11.5))
    o.append(text(392, 200, "counters and histograms; the ring only for discrete events", 9.5, 400, SOFT))
    o.append(line(620, 148, 620, 168, SIG, 1.6, None, True, "o"))
    o.append(line(0, 238, 720, 238, SIG, 1.3, "6 5"))
    o.append(text(8, 253, "USER SPACE", 10, 700, DEEP, spacing=1.2))
    o.append(card(258, 262, 200, 62, "shukrad (Go)", "reads the maps, joins them to the QEMU process, serves the API", cw(200, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(card(500, 262, 200, 62, "shukractl and console", "talk to the API only. They never load BPF", cw(200, 9.5), "#fff", INK, size=9.5, tsize=11.5))
    o.append(line(500, 293, 458, 293, SOFT, 1.6, None, True))
    o.append(line(420, 262, 420, 212, SIG, 1.5, "4 3", True, "o"))
    o.append(text(428, 254, "reads", 9, 700, DEEP))
    px = 8
    o.append(text(px, 285, "Why this is safe to run on a hypervisor", 11, 700, INK))
    for i, s in enumerate(["No agent, module or change inside any guest", "The verifier proves each program before it runs", "Programs observe; the tap program returns TCX_NEXT", "Only isolation and an enforced egress policy drop; both need an allow list"]):
        o.append(circle(px + 5, 302 + i * 17 - 3, 3.2, SIG))
        o.append(text(px + 16, 302 + i * 17, s, 9.5, 400, SOFT))
    return svg(720, 372, "".join(o), "How an eBPF program gets from source to a kernel hook and back to the daemon")


# ---------------------------------------------------------------- 2. where the hooks sit
def hypervisor():
    o = []
    lx, lw, hx, hw, h, gap = 10, 270, 352, 358, 46, 15
    layers = [
        ("Guest OS and applications", "never touched, no agent inside", "dash", None),
        ("KVM: the guest exits to the host", "every VM exit and re-entry", "on",
         ("kvm", "kvm_exit, kvm_entry, kvm_mmio, kvm_pio: exit counts by reason, handling time")),
        ("QEMU process threads: vCPU, iothread, vhost", "scheduled like any host thread", "on",
         ("sched", "wakeup, switch, exec, exit: run-queue delay, vCPU preemption and who had the CPU")),
        ("Block layer: the QEMU I/O thread", "the VM's disk requests as the host sees them", "on",
         ("block", "block_rq_issue and complete: latency histogram, bytes, slowest request")),
        ("QEMU process sockets", "QEMU's own connections, not the guest's", "on",
         ("net", "tcp_v4/v6_connect, sampled tcp_retransmit_skb: the QEMU process only")),
        ("The VMM itself, and what it starts", "a QEMU process that opens files or reaches around itself", "on",
         ("vmm", "openat, ptrace, mount, setns, module and kexec calls, and fork and exit: what a VMM never does")),
        ("VM tap (or the host veth vh*)", "where the guest's own traffic crosses", "on",
         ("tap", "TCX ingress and egress: guest flows, DNS and TLS names, handshakes, isolation, egress policy")),
        ("Host network stack, qdisc, NIC", "where packets are dropped and freed", "grey",
         ("drops", "skb:kfree_skb on the tap: the kernel's reason and the function that freed it")),
    ]
    y = 6
    for i, (title, sub, kind, hook) in enumerate(layers):
        if kind == "on":
            o.append(rect(lx, y, lw, h, PALE, SIG, 1.6, 9))
        elif kind == "dash":
            o.append(rect(lx, y, lw, h, "#fff", SOFT, 1.4, 9, "5 4"))
        else:
            o.append(rect(lx, y, lw, h, GREY, LINE, 1.4, 9))
        o.append(text(lx + 12, y + 20, title, 10.5, 700))
        o.append(text(lx + 12, y + 35, sub, 9, 400, SOFT))
        if hook:
            name, desc = hook
            o.append(rect(hx, y, hw, h, "#fff", SIG, 1.6, 9))
            o.append(text(hx + 12, y + 19, name, 11, 700, DEEP, mono=True))
            b, _ = lines(hx + 12, y + 33, desc, cw(hw, 9), 9, 10.5, 400, SOFT)
            o.append(b)
            o.append(line(lx + lw, y + h / 2, hx, y + h / 2, SIG, 1.3, "4 3"))
        if i < len(layers) - 1:
            o.append(line(lx + lw / 2, y + h, lx + lw / 2, y + h + gap, SOFT, 1.4, None, True))
        y += h + gap
    ly = y + 2
    o.append(rect(10, ly, 22, 12, PALE, SIG, 1.4, 4))
    o.append(text(38, ly + 10, "a program attaches here when the kernel supports it; the others keep running", 9, 400, SOFT))
    o.append(rect(10, ly + 20, 22, 12, GREY, LINE, 1.4, 4))
    o.append(text(38, ly + 30, "the Linux host as it is: Shukra observes it, it does not replace it", 9, 400, SOFT))
    o.append(text(10, ly + 52, "VM names, threads and tap names come from /proc and the QEMU command line, not from BPF or the guest.", 9, 400, SOFT, italic=True))
    return svg(720, ly + 62, "".join(o), "Where each Shukra program attaches on a KVM hypervisor")


# ---------------------------------------------------------------- 3. explain
def explain():
    o = []
    ev = [
        ("KVM exit handling time", "kvm"),
        ("Run-queue delay, vCPU preemption", "sched"),
        ("Block latency and throughput", "block"),
        ("TCP retransmits from QEMU", "net"),
        ("Tap: drops and handshake outcomes", "tap, drops"),
    ]
    o.append(text(0, 12, "EVIDENCE THE HOST ALREADY HAS", 9.5, 700, DEEP, spacing=1.1))
    ys = []
    for i, (t, p) in enumerate(ev):
        y = 24 + i * 52
        ys.append(y + 22)
        o.append(rect(0, y, 220, 44, "#fff", SIG, 1.4, 9))
        o.append(text(12, y + 19, t, 10.2, 700))
        o.append(text(12, y + 34, p, 9, 400, SOFT, mono=True))
    o.append(card(290, 88, 140, 104, "Explain", "deterministic rules over one window. No model, no guessing", cw(140, 9.5), PALE, SIG, size=9.5, tsize=12.5))
    for y in ys:
        o.append(line(220, y, 290, 140, SIG, 1.1, "4 3"))
    outs = [
        (24, "Ranked findings", "the cause, how sure, and the numbers behind it"),
        (108, "What Shukra cannot see", "listed on every answer, so silence is never read as health"),
        (192, "Any window", "the last 10 s to 5 min live; a past time from stored snapshots"),
    ]
    o.append(text(500, 12, "WHAT THE OPERATOR GETS", 9.5, 700, DEEP, spacing=1.1))
    for y, t, b in outs:
        o.append(card(500, y, 220, 72, t, b, cw(220, 9.5), "#fff", INK, size=9.5, tsize=11))
        o.append(line(430, 140, 500, y + 36, SOFT, 1.4, None, True))
    return svg(720, 290, "".join(o), "Explain turns the host's counters into ranked causes")


# ---------------------------------------------------------------- 4. contention
def contention():
    o = []
    o.append(text(0, 14, "payment-prod-03: vCPU threads runnable but off a host CPU, 240 ms in the window", 11, 700))
    bw = 720
    a = bw * 190 / 240
    o.append(rect(0, 28, a, 34, SIG, "none", 0, 6))
    o.append(rect(a, 28, bw - a, 34, "#c9c1b5", "none", 0, 6))
    o.append(text(12, 50, "vm:batch-etl-01   190 ms   79%", 11, 700, "#fff"))
    o.append(text(a + 8, 50, "kworker  50 ms", 10, 700, INK))
    o.append(line(0, 76, 720, 76, LINE, 1, "3 3"))
    o.append(card(0, 92, 226, 92, "Who had the CPU", "the thread that took it when a vCPU was switched out while still runnable: a VM by name, or a host command", cw(226, 9.5), "#fff", INK, size=9.5, tsize=11))
    o.append(card(247, 92, 226, 92, "One VM accounts for half or more", "then Explain names it: cause noisy_neighbour. cpu_preempted stays beside it", cw(226, 9.5), PALE, SIG, size=9.5, tsize=11))
    o.append(card(494, 92, 226, 92, "What it was doing meanwhile", "the culprit's own CPU, block and exit numbers over the same window", cw(226, 9.5), "#fff", INK, size=9.5, tsize=11))
    for x1, x2 in [(226, 247), (473, 494)]:
        o.append(line(x1, 138, x2, 138, SOFT, 1.6, None, True))
    return svg(720, 196, "".join(o), "A noisy neighbour named from vCPU preemption")


# ---------------------------------------------------------------- 5. a past time
def past_time():
    o = []
    ticks = [("02:55", 60), ("03:00", 180), ("03:05", 300), ("03:10", 420), ("03:15", 540), ("03:20", 660)]
    o.append(text(0, 14, "A COARSE SNAPSHOT EVERY 5 MINUTES (with -data-dir)", 9.5, 700, DEEP, spacing=1.1))
    o.append(line(20, 84, 700, 84, SOFT, 1.6))
    for lab, x in ticks:
        o.append(circle(x, 84, 6, SIG))
        o.append(text(x, 106, lab, 9.5, 700, INK, "middle", mono=True))
    o.append(path("M60,68 L60,60 L420,60 L420,68", DEEP, 1.4))
    o.append(text(240, 53, "a window earlier (--window, 15m here)  to  the snapshot at or before the time", 9.5, 700, DEEP, "middle"))
    o.append(line(468, 36, 468, 92, RED, 1.8, "4 3"))
    o.append(text(468, 30, "you ask: --at 03:12", 9.5, 700, RED, "middle"))
    o.append(card(0, 124, 226, 84, "The difference is the window", "built by the same code as a live verdict, and it states the resolution", cw(226, 9.5), PALE, SIG, size=9.5, tsize=11))
    o.append(card(247, 124, 226, 84, "Honest when it cannot", "nothing stored for that time? no_history, with the reason, never a guess", cw(226, 9.5), "#fff", INK, size=9.5, tsize=11))
    o.append(card(494, 124, 226, 84, "Incident bundle", "verdict, detections, recorder events, isolate requests, allow list and programs, in one file", cw(226, 9.5), "#fff", INK, size=9.5, tsize=11))
    for x1, x2 in [(226, 247), (473, 494)]:
        o.append(line(x1, 166, x2, 166, SOFT, 1.6, None, True))
    return svg(720, 218, "".join(o), "Explaining a past time from stored snapshots")


# ---------------------------------------------------------------- 6. handshakes and isolate
def handshake_isolate():
    o = []
    o.append(text(0, 12, "EVERY TCP CONNECT THE GUEST MAKES ENDS AS ONE OF FOUR", 9.5, 700, DEEP, spacing=1.1))
    o.append(card(0, 22, 128, 70, "Guest SYN", "seen on the tap", cw(128, 9.5), GREY, LINE, size=9.5, tsize=11))
    outs = [
        ("Accepted", "a SYN-ACK came back", "#fff", SIG),
        ("Refused", "an RST came back", "#fff", SIG),
        ("Never answered", "nothing in 3 s", "#fff", SIG),
        ("Blocked", "isolation dropped it", PALE, RED),
    ]
    o.append(rect(150, 14, 570, 86, "none", LINE, 1.2, 12, "5 4"))
    o.append(line(128, 57, 150, 57, SOFT, 1.6, None, True))
    for i, (t, b, f, s) in enumerate(outs):
        x = 160 + i * 140
        o.append(card(x, 22, 130, 70, t, b, cw(130, 9.5), f, s, size=9.5, tsize=11))
    o.append(text(168, 116,"attempts = accepted + refused + never answered + blocked (+ still waiting); a repeated SYN is a retransmit", 9, 400, SOFT, italic=True))
    o.append(line(0, 128, 720, 128, LINE, 1, "3 3"))
    o.append(text(0, 148, "CUT A VM OFF WITHOUT TOUCHING IT", 9.5, 700, DEEP, spacing=1.1))
    steps = [
        (0, "OBSERVE", "default", "nothing is dropped. The tap program only counts and reports", GREY, LINE),
        (190, "ISOLATE", "on request", "drops the VM's tap traffic except your management network. Refused without an allow list", PALE, SIG),
        (380, "RELEASE", "on request", "traffic flows again. Every request and its result is in the audit trail", GREY, LINE),
    ]
    for x, t, s, b, f, st in steps:
        o.append(rect(x, 158, 174, 92, f, st, 1.6, 9))
        o.append(text(x + 12, 178, t, 11.5, 700))
        o.append(text(x + 12, 192, s, 8.6, 700, DEEP))
        bb, _ = lines(x + 12, 207, b, cw(174, 9), 9, 10.8, 400, SOFT)
        o.append(bb)
    o.append(line(174, 204, 190, 204, SOFT, 1.6, None, True))
    o.append(line(364, 204, 380, 204, SOFT, 1.6, None, True))
    o.append(rect(570, 158, 150, 92, "#fff", INK, 1.4, 9))
    o.append(text(582, 178, "It outlives shukrad", 10.5, 700))
    bb, _ = lines(582, 194, "links and maps are pinned under /sys/fs/bpf/shukra/tap: a crash, restart or stop leaves the VM isolated", cw(150, 9), 9, 10.8, 400, SOFT)
    o.append(bb)
    return svg(720, 262, "".join(o), "TCP handshake outcomes and the observe, isolate, release lifecycle")


# ---------------------------------------------------------------- 7. the system
def system():
    o = []
    o.append(rect(0, 6, 430, 300, WARM, LINE, 1.2, 14, "5 4"))
    o.append(text(14, 26, "HYPERVISOR", 10, 700, DEEP, spacing=1.2))
    o.append(card(14, 38, 402, 46, "Guests (QEMU, libvirt, kubevirt, FluxVM)", "", 40, GREY, LINE, size=9.5, tsize=11))
    o.append(text(26, 74, "seen from outside; nothing is installed in them", 9, 400, SOFT))
    o.append(card(14, 100, 402, 62, "kvm  ·  sched  ·  block  ·  net  ·  vmm  ·  tap  ·  drops", "", 40, PALE, SIG, size=9.5, tsize=11))
    o.append(text(26, 134, "eBPF, CO-RE. Hot paths stay in maps; a small ring carries discrete events", 9, 400, SOFT))
    o.append(text(26, 148, "a program the kernel cannot support reports detached, with the reason", 9, 400, SOFT))
    o.append(line(215, 84, 215, 100, SOFT, 1.4, None, True))
    o.append(card(14, 182, 402, 62, "shukrad", "", 40, "#fff", INK, size=9.5, tsize=12))
    o.append(text(26, 214, "identity, sampler, rules, flight recorder, state, API on :30970", 9, 400, SOFT))
    o.append(text(26, 228, "bearer keys: an admin key, and a read-only key that cannot isolate", 9, 400, SOFT))
    o.append(line(215, 162, 215, 182, SIG, 1.5, "4 3", True, "o"))
    o.append(card(14, 256, 402, 40, "/var/lib/shukra  (0700)", "", 40, "#fff", LINE, size=9.5, tsize=10.5))
    o.append(text(190, 281, "detections · recorder · snapshots · policies · actions", 9, 400, SOFT))
    o.append(line(215, 244, 215, 256, SOFT, 1.2, "3 3"))
    outs = [
        (10, "shukractl and the console", "the operator loop: 21 commands, 16 pages", "#fff", INK, None),
        (70, "Prometheus", "GET /metrics with the read-only key", "#fff", INK, None),
        (130, "Alert sinks", "signed webhook, syslog, JSONL file", "#fff", INK, None),
        (190, "Detection rules", "one YAML file, reloaded on SIGHUP", "#fff", INK, None),
        (250, "PacketWolf and Zeus OS", "intended consumers of the JSON; not in this repo", GREY, LINE, "5 4"),
    ]
    for y, t, b, f, s, d in outs:
        o.append(rect(500, y, 220, 50, f, s, 1.4, 9, d))
        o.append(text(512, y + 19, t, 10.2, 700))
        bb, _ = lines(512, y + 33, b, cw(220, 9), 9, 10.5, 400, SOFT)
        o.append(bb)
        o.append(line(416, 213, 500, y + 25, SOFT, 1.1, "4 3", True))
    return svg(720, 312, "".join(o), "Shukra on a hypervisor and what connects to it")


# ---------------------------------------------------------------- 8. right-sizing
def rightsize():
    o = []
    o.append(text(0, 12, "WHAT THE ADVICE STANDS ON: THE SHARE OF EACH VM'S vCPU CAPACITY OVER THE WINDOW", 9.5, 700, DEEP, spacing=0.6))
    rows = [
        ("batch-etl-01", "8 vCPUs", (91, 7, 2), "overprovisioned: about 0.6 vCPUs used; 2 would leave twice the headroom it used"),
        ("payment-prod-03", "4 vCPUs", (10, 74, 16), "starved: preempted 17% of the time it wanted to run"),
    ]
    y = 26
    for name, cpus, (h, b, n), verdict in rows:
        o.append(text(0, y + 12, name, 10.5, 700))
        o.append(text(0, y + 25, cpus, 9, 400, SOFT))
        x0, w = 150, 560
        segs = [(h, "#c9c1b5", "halted", INK), (b, SIG, "busy", "#fff"), (n, "#efe9df", "", INK)]
        x = x0
        for pct, col, lab, tc in segs:
            sw = w * pct / 100
            o.append(rect(x, y, sw, 26, col, "none", 0, 0))
            if sw > 60 and lab:
                o.append(text(x + sw / 2, y + 17, f"{lab} {pct}%", 9.5, 700, tc, "middle"))
            elif pct >= 10 and not lab:
                o.append(text(x + sw / 2, y + 17, f"neither {pct}%", 9, 700, tc, "middle"))
            x += sw
        if b < 40 and h > 50:
            pass
        o.append(text(x0, y + 42, verdict, 9.2, 400, SOFT, italic=True))
        y += 62
    o.append(rect(150, y - 4, 12, 10, "#c9c1b5", "none", 0, 2))
    o.append(text(168, y + 5, "halted: HLT exit time, a lower bound on idleness", 8.8, 400, SOFT))
    o.append(rect(420, y - 4, 12, 10, SIG, "none", 0, 2))
    o.append(text(438, y + 5, "busy: the vCPU threads on a CPU", 8.8, 400, SOFT))
    o.append(rect(150, y + 12, 12, 10, "#efe9df", LINE, 1, 2))
    o.append(text(168, y + 21, "neither: never halted and not on a CPU (polling, MWAIT, or offline in the guest)", 8.8, 400, SOFT))
    y += 40
    cards = [
        ("Overprovisioned", "2 or more vCPUs, halted at least 80% and busy at most 20%"),
        ("Starved", "busy at least 50%, and preempted 10% or a vCPU waiting 2 ms for a CPU"),
        ("Nearly idle", "one vCPU, halted at least 95%: a consolidation candidate"),
    ]
    for i, (t, b) in enumerate(cards):
        x = i * 247
        o.append(card(x, y, 226, 66, t, b, cw(226, 9.5), "#fff", INK, size=9.5, tsize=11))
    return svg(720, y + 76, "".join(o), "How the right-sizing advisor reads a VM's vCPU capacity")


# ---------------------------------------------------------------- 9. learned baselines
def baseline():
    o = []
    o.append(text(0, 12, "A VM IS ONLY OBSERVED FIRST; THEN THE FIRST SIGHTING OF ANYTHING NEW IS REPORTED, ONCE", 9.5, 700, DEEP, spacing=0.6))
    o.append(rect(0, 24, 300, 36, GREY, LINE, 1.2, 8))
    o.append(text(12, 46, "learning: recorded, nothing reported", 10.2, 700))
    o.append(rect(300, 24, 420, 36, PALE, SIG, 1.4, 8))
    o.append(text(312, 46, "reporting: a first sighting becomes one detection", 10.2, 700))
    o.append(line(300, 20, 300, 68, DEEP, 1.4, "3 3"))
    o.append(text(0, 78, "first time the VM is seen", 9, 400, SOFT))
    o.append(text(300, 78, "24 h later (learn: 24h is the default)", 9, 700, DEEP, "middle"))
    kinds = [
        ("new-destination", "medium", "a network the guest never contacted before: the /24 of an IPv4 address, the /64 of an IPv6 address"),
        ("new-dns-suffix", "low", "a site it never looked up or asked for by TLS name: example.co.uk, not the host name in front of it"),
        ("new-inbound-peer", "medium", "a network that never connected in to the guest before"),
    ]
    for i, (t, sev, b) in enumerate(kinds):
        x = i * 247
        o.append(rect(x, 96, 226, 92, "#fff", SIG, 1.4, 9))
        o.append(text(x + 12, 116, t, 10.5, 700, DEEP, mono=True))
        o.append(text(x + 12, 130, "severity " + sev, 8.6, 700, SOFT))
        bb, _ = lines(x + 12, 145, b, cw(226, 9), 9, 10.5, 400, SOFT)
        o.append(bb)
    o.append(rect(0, 204, 720, 62, WARM, LINE, 1.2, 9))
    o.append(text(12, 222, "Bounded against a guest that controls what it says", 10.5, 700))
    bb, _ = lines(12, 237, "Fixed-size sets (2048 per kind); at most 20 alerts per VM per day, then one baseline-cap detection; unseen items are forgotten after 30 days. Off unless the rules file has a baselines: section.", cw(720, 9.2), 9.2, 11, 400, SOFT)
    o.append(bb)
    return svg(720, 276, "".join(o), "Learned baselines: a learning period, then first sightings reported once")


# ---------------------------------------------------------------- 10. VMM tripwires
def tripwire():
    o = []
    o.append(text(0, 12, "WHAT IS WATCHED", 9.5, 700, DEEP, spacing=1.1))
    o.append(rect(0, 24, 206, 44, PALE, SIG, 1.6, 9))
    o.append(text(12, 43, "A QEMU process (the VMM)", 10.5, 700))
    o.append(text(12, 58, "found from /proc, as for every program", 9, 400, SOFT))
    o.append(rect(0, 84, 206, 44, GREY, LINE, 1.4, 9))
    o.append(text(12, 103, "A shell it started", 10.5, 700))
    o.append(text(12, 118, "however deep: descent is recorded at fork", 9, 400, SOFT))
    o.append(rect(0, 144, 206, 44, GREY, LINE, 1.4, 9))
    o.append(text(12, 163, "What that shell ran, and so on", 10.5, 700))
    o.append(text(12, 178, "a job that outlives its parent is still followed", 9, 400, SOFT))
    o.append(line(103, 68, 103, 84, SOFT, 1.4, None, True))
    o.append(line(103, 128, 103, 144, SOFT, 1.4, None, True))

    o.append(text(246, 12, "THE vmm PROGRAM", 9.5, 700, DEEP, spacing=1.1))
    o.append(rect(246, 24, 216, 164, "#fff", SIG, 1.6, 9))
    o.append(text(258, 43, "13 syscall tracepoints, fork and exit", 10.5, 700))
    y = 60
    for t in ["openat, openat2, open: the file, as the process gave it", "ptrace, process_vm_readv and writev, mount, unshare, setns, module and kexec loads: with their arguments", "at most 300 reported a second for a VMM and everything it started"]:
        b, h = lines(270, y, t, cw(196, 9), 9, 10.8, 400, SOFT)
        o.append(circle(261, y - 3, 2.6, SIG))
        o.append(b)
        y += h + 6
    o.append(line(206, 106, 246, 106, SIG, 1.6, None, True, "o"))

    o.append(text(502, 12, "shukrad JUDGES IT", 9.5, 700, DEEP, spacing=1.1))
    o.append(rect(502, 24, 218, 44, GREY, LINE, 1.4, 9))
    o.append(text(514, 43, "Sensitive list, path cleaned first", 10.5, 700))
    o.append(text(514, 58, "decided in the daemon, so it can change", 9, 400, SOFT))
    dets = [("vmm-sensitive-open", "critical"), ("vmm-syscall", "critical or high"), ("vmm-flood", "critical")]
    for i, (n, sev) in enumerate(dets):
        yy = 84 + i * 36
        o.append(rect(502, yy, 218, 30, "#fff", SIG, 1.4, 8))
        o.append(text(514, yy + 19, n, 9.6, 700, DEEP, mono=True))
        o.append(text(708, yy + 19, sev, 9, 700, SOFT, "end"))
    o.append(line(462, 46, 502, 46, SIG, 1.6, None, True, "o"))
    o.append(line(611, 68, 611, 84, SOFT, 1.4, None, True))
    o.append(text(0, 214, "It reports; it does not stop anything. Isolation cuts the guest's network at its tap, not a process in the VMM's tree.", 9.5, 400, SOFT, italic=True))
    return svg(720, 226, "".join(o), "The VMM tripwire: what is watched, the vmm program and the detections it raises")


# ---------------------------------------------------------------- 11. egress policy
def policy_flow():
    o = []
    o.append(text(0, 12, "THREE STAGES, EACH SAFER THAN THE NEXT IS RISKY", 9.5, 700, DEEP, spacing=1.1))
    stages = [
        (0, "1  LEARN", "the VM's baseline, as a list of networks (/24 and /64)", "shukractl policy learn web: a proposal, and how it differs from what the VM has. Nothing changes", GREY, LINE),
        (260, "2  AUDIT", "drops nothing", "what would have been dropped is counted and reported. policy apply web --mode audit --from-baseline", PALE, SIG),
        (520, "3  ENFORCE", "with a timer", "drops what the VM starts outside the list. policy apply web --mode enforce --confirm 10m", PALE, SIG),
    ]
    for x, t, sub, b, f, st in stages:
        o.append(rect(x, 24, 200, 124, f, st, 1.6, 9))
        o.append(text(x + 12, 44, t, 11.5, 700))
        o.append(text(x + 12, 58, sub, 8.8, 700, DEEP))
        bb, _ = lines(x + 12, 74, b, cw(200, 9), 9, 10.8, 400, SOFT)
        o.append(bb)
    o.append(line(200, 86, 260, 86, SOFT, 1.6, None, True))
    o.append(line(460, 86, 520, 86, SOFT, 1.6, None, True))
    o.append(line(575, 148, 505, 168, SOFT, 1.5, None, True))
    o.append(line(665, 148, 665, 168, RED, 1.5, "4 3", True, "r"))
    o.append(rect(400, 168, 210, 50, "#fff", INK, 1.4, 9))
    o.append(text(412, 187, "Confirmed: it stays", 10.5, 700))
    o.append(text(412, 203, "policy confirm web", 9, 400, SOFT, mono=True))
    o.append(rect(630, 168, 90, 50, "#fff8f6", RED, 1.4, 9))
    o.append(text(640, 187, "Time is up", 10.5, 700, RED))
    o.append(text(640, 203, "goes back", 9, 400, SOFT))
    b, _ = lines(0, 184, "Even if the daemon was down when the time ran out: it reverts on its first pass after it starts, and until then the kernel keeps enforcing.", cw(380, 9.5), 9.5, 12, 400, SOFT)
    o.append(b)
    o.append(rect(0, 236, 720, 34, WARM, SIG, 1.4, 9))
    o.append(text(12, 257, "The management allow list (-isolate-allow) is never judged, whatever a policy says. A wrong policy cannot cut a VM off from the network that manages it.", 9.5, 700))
    return svg(720, 278, "".join(o), "An egress policy: learn, audit, enforce with a timer, and the management floor")


# ---------------------------------------------------------------- 12. responses
def response_flow():
    o = []
    o.append(text(0, 12, "A RESPONSE CAN DO ONE THING: ISOLATE THE VM. BY DEFAULT IT ONLY PROPOSES", 9.5, 700, DEEP, spacing=0.8))
    steps = [
        ("Detection", "a rule fires for a VM", GREY, LINE),
        ("Response", "matches a rule you named", GREY, LINE),
        ("Guardrails", "protected list, cap, cooldown", PALE, SIG),
        ("Propose", "pending. Bundle captured, announced", PALE, SIG),
        ("A person", "approves, or rejects. A lapse does nothing", "#fff", INK),
        ("Isolated", "at the tap; the allow list stays reachable", PALE, SIG),
    ]
    w, gap = 108, 14.4
    xs = []
    for i, (t, b, f, st) in enumerate(steps):
        x = i * (w + gap)
        xs.append(x)
        o.append(rect(x, 24, w, 84, f, st, 1.6, 9))
        o.append(text(x + 10, 43, t, 10.5, 700))
        bb, _ = lines(x + 10, 58, b, cw(w, 8.8), 8.8, 10.6, 400, SOFT)
        o.append(bb)
        if i < len(steps) - 1:
            o.append(line(x + w, 66, x + w + gap, 66, SOFT, 1.5, None, True))
    gx = xs[2] + w / 2
    ix = xs[5] + w / 2
    o.append(path(f"M{gx},108 L{gx},134 L{ix},134 L{ix},110", SIG, 1.5, "4 3", True, marker="o"))
    o.append(text((gx + ix) / 2, 128, "mode: enforce, for the rules it names only: carried out at once", 9, 700, DEEP, "middle"))
    o.append(text(0, 158, "dry_run: true records what would have been done and changes nothing, so a response can be tried on real detections first.", 9.2, 400, SOFT, italic=True))
    return svg(720, 168, "".join(o), "A detection becomes a proposal that a person decides, or, only for named rules, an isolation")


ALL = {
    "ebpf": ebpf_pipeline,
    "hypervisor": hypervisor,
    "explain": explain,
    "contention": contention,
    "pasttime": past_time,
    "handshake": handshake_isolate,
    "system": system,
    "rightsize": rightsize,
    "baseline": baseline,
    "tripwire": tripwire,
    "policyflow": policy_flow,
    "responseflow": response_flow,
}
