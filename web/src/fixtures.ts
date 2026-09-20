export const fixtureMode = import.meta.env.VITE_FIXTURE === '1';

const now = '2026-09-19T09:42:10Z';

// A 64-bucket log2 histogram with the given counts starting at bucket `from`.
const hist = (from: number, counts: number[]) => Array.from({ length: 64 }, (_, i) => counts[i - from] ?? 0);

const guest = (name: string, runtime: string) => ({ vm: { name, runtime }, attribution: 'guest-tap', guest_attributed: true });

export const fixture = {
  status: {
    version: '0.1.0',
    product: 'shukra',
    tagline: 'eBPF-powered runtime intelligence and security for KVM',
    mode: 'observe',
    datapath: 'tracepoint-kprobe',
    healthy: true,
    vms: 3,
    programsAttached: 6,
    programsTotal: 6,
    detections: 3,
    summary: 'observe: host traces, and guest traffic on the VM taps (3 taps: tap1, tap2, tap7)',
  },
  vms: [
    { name: 'payment-prod-03', uuid: '8f3c2a10-1111-2222-3333-444455556666', runtime: 'kubevirt', hypervisor: 'node-07', pid: 19321, taps: ['tap7'], comm: 'qemu-system-x86_64', threadInfo: [{ tid: 19321, comm: 'qemu-system-x86', role: 'other' }, { tid: 19322, comm: 'CPU 0/KVM', role: 'vcpu' }, { tid: 19323, comm: 'IO iothread1', role: 'iothread' }, { tid: 19324, comm: 'vhost-19321', role: 'vhost' }] },
    { name: 'api-01', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'libvirt', hypervisor: 'node-07', pid: 20100, taps: ['tap1'], comm: 'qemu-system-x86_64', threadInfo: [{ tid: 20100, comm: 'qemu-system-x86', role: 'other' }, { tid: 20101, comm: 'CPU 0/KVM', role: 'vcpu' }, { tid: 20102, comm: 'CPU 1/KVM', role: 'vcpu' }, { tid: 20103, comm: 'IO iothread1', role: 'iothread' }, { tid: 20104, comm: 'vhost-20100', role: 'vhost' }] },
    { name: 'redis-01', uuid: 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'qemu', hypervisor: 'node-07', pid: 21010, taps: ['tap2'], comm: 'qemu-system-x86_64', threadInfo: [{ tid: 21010, comm: 'qemu-system-x86', role: 'other' }, { tid: 21011, comm: 'CPU 0/KVM', role: 'vcpu' }, { tid: 21012, comm: 'vhost-21010', role: 'vhost' }] },
  ],
  programs: [
    { name: 'kvm', status: 'attached', detail: '4 tracepoints: kvm_exit, kvm_entry, kvm_mmio, kvm_pio' },
    { name: 'sched', status: 'attached', detail: '4 tracepoints: sched_wakeup, sched_switch, sched_process_exec, sched_process_exit' },
    { name: 'block', status: 'attached', detail: '2 tracepoints: block_rq_issue, block_rq_complete' },
    { name: 'net', status: 'attached', detail: 'tcp_v4_connect, tcp_v6_connect, sampled tcp_retransmit_skb. Host TCP only: the QEMU process, not the guest.' },
    { name: 'tap', status: 'attached', detail: 'TCX ingress and egress on 3 taps: tap1, tap2, tap7' },
    { name: 'drops', status: 'attached', detail: 'skb:kfree_skb, filtered to 3 VM taps' },
  ],
  kvm: [{ vm: 'payment-prod-03', runtime: 'kubevirt', exits: 182000, entries: 181200, mmio: 420, pio: 12, measured: true, topReasons: [{ reason: 30, count: 90000, totalNs: 4200000000, name: 'io_instruction' }, { reason: 12, count: 40000, totalNs: 91000000000, name: 'hlt' }], topReasonsByTime: [{ reason: 12, count: 40000, totalNs: 91000000000, name: 'hlt' }, { reason: 30, count: 90000, totalNs: 4200000000, name: 'io_instruction' }], exitLatencyP50Ns: 4096, exitLatencyP99Ns: 262144, exitLatencyHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9000, 61000, 70000, 30000, 9000, 2500, 400, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, { vm: 'api-01', runtime: 'libvirt', exits: 96000, entries: 95800, mmio: 210, pio: 8, measured: true, topReasons: [{ reason: 1, count: 51000, totalNs: 1900000000, name: 'external_interrupt' }, { reason: 12, count: 30000, totalNs: 64000000000, name: 'hlt' }], topReasonsByTime: [{ reason: 12, count: 30000, totalNs: 64000000000, name: 'hlt' }, { reason: 1, count: 51000, totalNs: 1900000000, name: 'external_interrupt' }], exitLatencyP50Ns: 2048, exitLatencyP99Ns: 65536, exitLatencyHist: hist(10, [4000, 32000, 40000, 14000, 4500, 900, 120, 10]) }, { vm: 'redis-01', runtime: 'qemu', exits: 41000, entries: 40900, mmio: 90, pio: 3, measured: true, topReasons: [{ reason: 12, count: 21000, totalNs: 52000000000, name: 'hlt' }], topReasonsByTime: [{ reason: 12, count: 21000, totalNs: 52000000000, name: 'hlt' }], exitLatencyP50Ns: 2048, exitLatencyP99Ns: 32768, exitLatencyHist: hist(10, [2000, 16000, 17000, 5000, 900, 90, 8]) }],
  sched: [{ vm: 'payment-prod-03', onCpuNs: 870000000, wakeupDelayNs: 14000000, wakeupCount: 2200, wakeupDelayP50Ns: 4096, wakeupDelayP99Ns: 65536, vcpuPreemptedNs: 240000000, vcpuPreemptions: 31, topPreemptors: [{ who: 'vm:api-01', ns: 190000000 }, { who: 'kworker', ns: 50000000 }], wakeupHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 700, 800, 260, 110, 24, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], measured: true }, { vm: 'api-01', onCpuNs: 41000000000, wakeupDelayNs: 22000000, wakeupCount: 6100, wakeupDelayP50Ns: 2048, wakeupDelayP99Ns: 32768, vcpuPreemptedNs: 70000000, vcpuPreemptions: 22, topPreemptors: [{ who: 'vm:payment-prod-03', ns: 25000000 }, { who: 'kworker', ns: 30000000 }], wakeupHist: hist(9, [900, 2400, 1900, 640, 210, 40, 10]), measured: true }, { vm: 'redis-01', onCpuNs: 6200000000, wakeupDelayNs: 5000000, wakeupCount: 3300, wakeupDelayP50Ns: 2048, wakeupDelayP99Ns: 16384, vcpuPreemptedNs: 95000000, vcpuPreemptions: 17, topPreemptors: [{ who: 'vm:api-01', ns: 60000000 }, { who: 'cilium-agent', ns: 30000000 }], wakeupHist: hist(9, [1000, 1500, 600, 160, 30, 8, 2]), measured: true }],
  schedThreads: [{ vm: 'payment-prod-03', tid: 19322, comm: 'CPU 0/KVM', role: 'vcpu', onCpuNs: 610000000, wakeupDelayNs: 9000000, wakeupCount: 1500, wakeupDelayP99Ns: 65536, preemptedNs: 240000000 }, { vm: 'payment-prod-03', tid: 19323, comm: 'IO iothread1', role: 'iothread', onCpuNs: 90000000, wakeupDelayNs: 4000000, wakeupCount: 700, wakeupDelayP99Ns: 32768 }],
  block: [{ vm: 'payment-prod-03', issues: 940, readP50Ns: 1200000, readP99Ns: 8400000, writeP50Ns: 3000000, writeP99Ns: 21000000, readMaxNs: 12000000, writeMaxNs: 28000000, readOps: 610, writeOps: 330, readBytes: 41943040, writeBytes: 25165824, readHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 210, 260, 70, 20, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], writeHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 60, 120, 90, 30, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], measured: true }, { vm: 'api-01', issues: 410, readP50Ns: 300000, readP99Ns: 2100000, writeP50Ns: 700000, writeP99Ns: 4200000, readMaxNs: 3400000, writeMaxNs: 6100000, readOps: 290, writeOps: 120, readBytes: 12582912, writeBytes: 5242880, readHist: hist(16, [10, 60, 110, 70, 30, 8, 2]), writeHist: hist(17, [8, 30, 44, 24, 10, 4]), measured: true }, { vm: 'redis-01', issues: 65, readP50Ns: 200000, readP99Ns: 900000, writeP50Ns: 500000, writeP99Ns: 1800000, readMaxNs: 1200000, writeMaxNs: 2100000, readOps: 20, writeOps: 45, readBytes: 786432, writeBytes: 2359296, readHist: hist(16, [4, 9, 6, 1]), writeHist: hist(17, [6, 20, 15, 4]), measured: true }],
  net: {
    attribution: 'qemu-process',
    guestAttributed: false,
    note: 'These are connects from the QEMU process, not the guest.',
    rows: [
      { vm: 'payment-prod-03', connects: 183, retransmits: 19, attribution: 'qemu-process', guest_attributed: false, note: 'Connects and retransmits from the QEMU process, not the guest.' },
      { vm: 'api-01', connects: 61, retransmits: 4, attribution: 'qemu-process', guest_attributed: false, note: 'Connects and retransmits from the QEMU process, not the guest.' },
    ],
  },
  events: [
    { product: 'shukra', kind: 'exec', ts: '2026-09-19T09:41:12Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19321, comm: 'qemu-system-x86_64', message: 'QEMU thread exec' },
    { product: 'shukra', kind: 'tcp_connect', ts: '2026-09-19T09:41:31Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19321, dst: '10.0.4.12', dport: 6443 },
    { product: 'shukra', kind: 'tcp_connect', ts: '2026-09-19T09:41:48Z', vm: { name: 'api-01', runtime: 'libvirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 20100, dst: '10.0.4.20', dport: 2049 },
    { product: 'shukra', kind: 'tcp_retransmit', ts: '2026-09-19T09:41:52Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19321, dst: '10.0.4.20', dport: 2049 },
    { product: 'shukra', kind: 'block_slow', ts: '2026-09-19T09:41:55Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19323, comm: 'IO iothread1', latency_ns: 28000000, message: 'write took 28 ms' },
    { product: 'shukra', kind: 'sched_delay', ts: '2026-09-19T09:41:58Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19322, comm: 'CPU 0/KVM', latency_ns: 2100000, message: 'vCPU runnable 2.1 ms before it got a CPU' },
    { product: 'shukra', kind: 'guest_dns', ts: '2026-09-19T09:42:01Z', ...guest('payment-prod-03', 'kubevirt'), iface: 'tap7', proto: 'udp', src: '10.0.0.31', dst: '10.0.0.2', dport: 53, dns_name: 'ledger.internal.example', qtype: 'A' },
    { product: 'shukra', kind: 'guest_tls', ts: '2026-09-19T09:42:02Z', ...guest('payment-prod-03', 'kubevirt'), iface: 'tap7', proto: 'tcp', src: '10.0.0.31', dst: '10.0.4.12', dport: 443, sni: 'ledger.internal.example', alpn: 'h2,http/1.1', tls_version: '1.3', ja3: '375c6162a492dfbf2795909110ce8424' },
    { product: 'shukra', kind: 'guest_connect', ts: '2026-09-19T09:42:03Z', ...guest('payment-prod-03', 'kubevirt'), iface: 'tap7', proto: 'tcp', src: '10.0.0.31', dst: '10.0.4.12', dport: 5432 },
    { product: 'shukra', kind: 'guest_connect', ts: '2026-09-19T09:42:04Z', ...guest('payment-prod-03', 'kubevirt'), iface: 'tap7', proto: 'tcp', src: '10.0.0.31', dst: '185.1.2.3', dport: 443, blocked: true },
    { product: 'shukra', kind: 'guest_flow', ts: '2026-09-19T09:42:05Z', ...guest('api-01', 'libvirt'), iface: 'tap1', proto: 'udp', src: '10.0.0.12', dst: '10.0.0.53', dport: 5353 },
    { product: 'shukra', kind: 'guest_inbound', ts: '2026-09-19T09:42:06Z', ...guest('api-01', 'libvirt'), iface: 'tap1', proto: 'tcp', src: '10.0.9.4', dst: '10.0.0.12', dport: 22 },
    { product: 'shukra', kind: 'guest_dns', ts: '2026-09-19T09:42:07Z', ...guest('redis-01', 'qemu'), iface: 'tap2', proto: 'udp', src: '10.0.0.44', dst: '10.0.0.2', dport: 53, dns_name: 'pool.nanopool.org', qtype: 'A' },
    { product: 'shukra', kind: 'guest_tls', ts: '2026-09-19T09:42:08Z', ...guest('redis-01', 'qemu'), iface: 'tap2', proto: 'tcp', src: '10.0.0.44', dst: '203.0.113.50', dport: 3333, sni: 'pool.nanopool.org', tls_version: '1.2', tls_truncated: true },
    { product: 'shukra', kind: 'detection', ts: '2026-09-19T09:42:04Z', ...guest('payment-prod-03', 'kubevirt'), dst: '185.1.2.3', dport: 443, rule: 'unexpected-egress', severity: 'high', message: 'unexpected-egress destination 185.1.2.3' },
    { product: 'shukra', kind: 'detection', ts: '2026-09-19T09:42:07Z', ...guest('redis-01', 'qemu'), dst: '10.0.0.2', dport: 53, rule: 'crypto-pool', severity: 'high', message: 'crypto-pool: guest looked up pool.nanopool.org' },
    { product: 'shukra', kind: 'detection', ts: now, ...guest('api-01', 'libvirt'), dst: '10.0.9.4', dport: 22, rule: 'ssh-into-vm', severity: 'medium', message: 'ssh-into-vm: a connection made to the guest on port 22' },
  ],
};

export function fixtureResponse(path: string, init?: RequestInit): unknown {
  const url = new URL(path, 'http://shukra.local');
  const vm = url.searchParams.get('vm');
  if (url.pathname === '/api/v1/status') return fixture.status;
  if (url.pathname === '/api/v1/vms') return { vms: fixture.vms };
  if (url.pathname === '/api/v1/programs') return { programs: fixture.programs };
  if (url.pathname === '/api/v1/trace/kvm') return { rows: filter(fixture.kvm, vm) };
  if (url.pathname === '/api/v1/trace/sched') {
    const rows = filter(fixture.sched, vm);
    return url.searchParams.get('threads') === '1' ? { rows, threads: filter(fixture.schedThreads, vm) } : { rows };
  }
  if (url.pathname === '/api/v1/trace/block') return { rows: filter(fixture.block, vm) };
  if (url.pathname === '/api/v1/trace/drops') {
    return {
      attribution: 'guest-tap',
      guestAttributed: true,
      measured: true,
      note: 'Sample rows.',
      taps: [
        { vm: 'payment-prod-03', tap: 'tap7', kernelDrops: 1290, shukraDropped: 0, otherDrops: 1204, guestNotReading: 0, reasons: [{ reason: 'NETFILTER_DROP', count: 1204 }, { reason: 'NO_SOCKET', count: 86 }] },
        { vm: 'api-01', tap: 'tap1', kernelDrops: 14, shukraDropped: 0, otherDrops: 3, guestNotReading: 11, reasons: [{ reason: 'FULL_RING', count: 11 }, { reason: 'NO_SOCKET', count: 3 }] },
        { vm: 'redis-01', tap: 'tap2', kernelDrops: 0, shukraDropped: 0, otherDrops: 0, guestNotReading: 0, reasons: [] },
      ],
      rows: [
        { vm: 'payment-prod-03', tap: 'tap7', reason: 'NETFILTER_DROP', count: 1204, location: 'nft_do_chain' },
        { vm: 'payment-prod-03', tap: 'tap7', reason: 'NO_SOCKET', count: 86, location: '__udp4_lib_rcv' },
        { vm: 'api-01', tap: 'tap1', reason: 'FULL_RING', count: 11, location: 'tun_net_xmit' },
        { vm: 'api-01', tap: 'tap1', reason: 'NO_SOCKET', count: 3, location: '__udp4_lib_rcv' },
      ],
    };
  }
  if (url.pathname === '/api/v1/actions') {
    return {
      enabled: true,
      pending: 1,
      note: 'Sample rows.',
      actions: [
        { id: 'a-3', vm: 'payment-prod-03', response: 'contain-miners', mode: 'propose', rule: 'crypto-pool', severity: 'high', message: 'payment-prod-03 looked up eth.nanopool.org (A)', status: 'pending', created: '2026-09-20T03:00:00Z', expires: '2026-09-20T03:30:00Z' },
        { id: 'a-2', vm: 'batch-etl-01', response: 'contain-miners', mode: 'propose', rule: 'crypto-pool', severity: 'high', message: 'batch-etl-01 looked up nanopool.org (A)', status: 'executed', created: '2026-09-19T21:00:00Z', decidedBy: 'approved by alice (contain-miners, a-2)', result: 'isolated: 1 tap', releaseAt: '2026-09-19T21:15:00Z' },
        { id: 'a-1', vm: 'redis-01', response: 'contain-miners', mode: 'propose', rule: 'crypto-pool', severity: 'high', message: 'redis-01 looked up nanopool.org (A)', status: 'refused', created: '2026-09-19T20:00:00Z', guardrail: 'never_isolate', result: 'redis-01 is protected: no response may isolate it' },
      ],
    };
  }
  if (url.pathname === '/api/v1/advice') {
    return {
      note: 'Sample rows.',
      window: '5m0s',
      rows: [
        { vm: 'batch-etl-01', vcpus: 8, window: '5m0s', idleAvailable: true, idleFraction: 0.91, busyFraction: 0.07, busyVcpus: 0.6, preemptShare: 0, unaccountedFraction: 0.02, runqueueDelayP99Ns: 65536, advice: [{ kind: 'overprovisioned', confidence: 'medium', summary: 'This VM has 8 vCPUs and used about 0.6 of them. 2 would leave it twice the headroom it used.', evidence: ['Halted 91% of the time.'] }] },
        { vm: 'payment-prod-03', vcpus: 4, window: '5m0s', idleAvailable: true, idleFraction: 0.1, busyFraction: 0.74, busyVcpus: 3.0, preemptShare: 0.17, unaccountedFraction: 0.16, runqueueDelayP99Ns: 33000000, advice: [{ kind: 'starved', confidence: 'high', summary: 'This VM wants more CPU than the host gives it.', evidence: ['Preempted 17% of the time it wanted to run.'] }] },
      ],
    };
  }
  if (url.pathname === '/api/v1/trace/contention') {
    return {
      note: 'Sample rows.',
      window: '1m0s',
      pairs: [
        { victim: 'payment-prod-03', culprit: 'api-01', preemptedNs: 190000000, share: 0.79 },
        { victim: 'redis-01', culprit: 'api-01', preemptedNs: 60000000, share: 0.63 },
        { victim: 'api-01', culprit: 'payment-prod-03', preemptedNs: 25000000, share: 0.36 },
      ],
      victims: [
        { vm: 'payment-prod-03', preemptedNs: 240000000, preemptions: 31, byOtherVmsNs: 190000000, bySelfNs: 0, byHostNs: 50000000, topHostTasks: [{ who: 'kworker', ns: 50000000 }] },
        { vm: 'redis-01', preemptedNs: 95000000, preemptions: 17, byOtherVmsNs: 60000000, bySelfNs: 5000000, byHostNs: 30000000, topHostTasks: [{ who: 'cilium-agent', ns: 30000000 }] },
        { vm: 'api-01', preemptedNs: 70000000, preemptions: 22, byOtherVmsNs: 25000000, bySelfNs: 15000000, byHostNs: 30000000, topHostTasks: [{ who: 'kworker', ns: 30000000 }] },
      ],
      culprits: [
        { vm: 'api-01', tookNs: 250000000, victims: 2, onCpuNs: 41000000000, exits: 96000 },
        { vm: 'payment-prod-03', tookNs: 25000000, victims: 1, onCpuNs: 870000000, exits: 182000 },
      ],
    };
  }
  if (url.pathname === '/api/v1/trace/tap') {
    const rows = [
      { vm: 'payment-prod-03', tap: 'tap7', fromGuestPackets: 412000, fromGuestBytes: 96000000, toGuestPackets: 398000, toGuestBytes: 121000000, droppedPackets: 1290, droppedBytes: 1800000, isolated: false, outSyn: 1240, outAccepted: 1180, outRefused: 22, outTimedOut: 31, outRetransmits: 40, outBlocked: 0, inSyn: 96, inAccepted: 94, inRefused: 2, inIgnored: 0, inRetransmits: 1, inBlocked: 0, handshakeP50Ns: 262144, handshakeP99Ns: 8388608 },
      { vm: 'api-01', tap: 'tap1', fromGuestPackets: 96000, fromGuestBytes: 21000000, toGuestPackets: 91000, toGuestBytes: 30000000, droppedPackets: 14, droppedBytes: 9000, isolated: false, outSyn: 310, outAccepted: 306, outRefused: 3, outTimedOut: 1, outRetransmits: 2, outBlocked: 0, inSyn: 44, inAccepted: 44, inRefused: 0, inIgnored: 0, inRetransmits: 0, inBlocked: 0, handshakeP50Ns: 131072, handshakeP99Ns: 1048576 },
      { vm: 'redis-01', tap: 'tap2', fromGuestPackets: 33000, fromGuestBytes: 5000000, toGuestPackets: 31000, toGuestBytes: 6000000, droppedPackets: 0, droppedBytes: 0, isolated: false, outSyn: 12, outAccepted: 12, outRefused: 0, outTimedOut: 0, outRetransmits: 0, outBlocked: 0, inSyn: 208, inAccepted: 208, inRefused: 0, inIgnored: 0, inRetransmits: 0, inBlocked: 0, handshakeP50Ns: 65536, handshakeP99Ns: 262144 },
    ];
    return { attribution: 'guest-tap', guestAttributed: true, note: 'Sample rows.', rows: filter(rows, vm) };
  }
  if (url.pathname === '/api/v1/security') {
    return { vm: vm || '', detections: fixture.events.filter((e) => e.kind === 'detection'), enforcement: 'tcx', allowList: ['10.0.0.0/24', '10.0.9.4'], durable: true };
  }
  if ((url.pathname === '/api/v1/isolate' || url.pathname === '/api/v1/release') && init?.method === 'POST') {
    const action = url.pathname.endsWith('release') ? 'release' : 'isolate';
    const body = JSON.parse(String(init?.body || '{}')) as { vm?: string };
    return { vm: body.vm || 'payment-prod-03', enforcement: 'tcx', applied: true, taps: ['tap7'], reason: action === 'isolate' ? 'Its tap drops everything except the management allow list.' : 'Its tap is open again.', audit: { action, result: 'applied' } };
  }
  if (url.pathname === '/api/v1/isolations') {
    return { isolations: [{ ts: '2026-09-19T09:30:41Z', vm: 'redis-01', action: 'isolate', actor: 'ops', enforcement: 'tcx', applied: true, result: 'applied' }, { ts: '2026-09-19T09:33:02Z', vm: 'redis-01', action: 'release', actor: 'ops', enforcement: 'tcx', applied: true, result: 'applied' }] };
  }
  if (url.pathname === '/api/v1/trace/net') return { ...fixture.net, rows: filter(fixture.net.rows, vm) };
  if (url.pathname === '/api/v1/events') return { events: filterEvents(vm) };
  if (url.pathname === '/api/v1/detections') {
    return { vm, detections: fixture.events.filter((e) => e.kind === 'detection' && (!vm || e.vm.name === vm)), enforcement: 'tcx' };
  }
  if (url.pathname === '/api/v1/recorder') {
    return { window: url.searchParams.get('window') || '60s', events: filterEvents(vm) };
  }
  if (url.pathname === '/api/v1/incident') {
    return { vm: fixture.vms.find((v) => v.name === vm) || { name: vm || '' }, at: url.searchParams.get('at') || now, events: filterEvents(vm), detections: fixture.events.filter((e) => e.kind === 'detection'), isolations: [], allowList: ['10.0.0.0/24', '10.0.9.4'] };
  }
  if (url.pathname === '/api/v1/explain') {
    return {
      vm: fixture.vms.find((v) => v.name === vm) || { name: vm || '', runtime: '' },
      question: 'why is this VM slow?',
      window: '1m0s',
      basis: 'Latencies are since the daemon attached, from log2 buckets, so each can read up to 2x high. They are the QEMU process\'s, not the guest\'s.',
      findings: [
        { cause: 'noisy_neighbour', confidence: 'high', summary: 'Another VM, api-01, took most of the CPU this VM\'s vCPUs were denied. Look at api-01\'s load, and at CPU pinning or separating the two onto different cores.', evidence: ['api-01 took 190 ms of the 240 ms the vCPUs were preempted (79%). shukractl trace contention shows what api-01 was doing meanwhile.'] },
        { cause: 'storage_latency', confidence: 'high', summary: 'Block requests from QEMU take long. Look at the backing device, its queue depth and other writers.', evidence: ['Block write p99 is up to 33.6 ms (slowest 28 ms) across 940 requests.'] },
        { cause: 'cpu_preempted', confidence: 'high', summary: 'The host took CPU away from this VM\'s vCPUs. Look at what else is running on those host CPUs: other VMs, host services, interrupt load, and CPU pinning.', evidence: ['The vCPU threads were runnable but off a host CPU for 240 ms over 31 preemptions, 28% of the time they wanted to run.'] },
        { cause: 'guest_traffic_dropped', confidence: 'medium', summary: 'The host kernel is dropping this VM\'s packets, and Shukra\'s isolation is not the cause. Look for another program attached to the tap (Cilium, a network dataplane, a tc filter): bpftool net show dev tap7.', evidence: ['1204 packets were dropped on tap tap7 by something other than Shukra (Shukra dropped 0). Mostly NETFILTER_DROP.'] },
      ],
      evidence: [
        'Identity comes from the QEMU command line, not from inside the guest.',
        'KVM exit counters are present for this thread group.',
        'The sched program measured this VM\'s vCPU preemption and named who had the CPU.',
        'The tap program is attached to tap7: the guest\'s own connections and their outcomes are counted.',
        'TCP connects from the QEMU process are not guest flows.',
      ],
      missing: [
        'CPU steal as the guest counts it (Shukra measures the host\'s view: how long the vCPUs were preempted)',
        'in-guest process identity',
      ],
      events: filterEvents(vm),
    };
  }
  throw new Error('no fixture for ' + path);
}

function filter<T extends { vm: string }>(rows: T[], vm: string | null): T[] {
  if (!vm) return rows;
  return rows.filter((r) => r.vm === vm);
}

function filterEvents(vm: string | null) {
  if (!vm) return fixture.events;
  return fixture.events.filter((e) => e.vm.name === vm);
}
