export const fixtureMode = import.meta.env.VITE_FIXTURE === '1';

const now = '2026-09-19T09:42:10Z';

export const fixture = {
  status: {
    version: '0.1.0',
    product: 'shukra',
    tagline: 'eBPF-powered runtime intelligence and security for KVM',
    mode: 'observe',
    datapath: 'tracepoint-kprobe',
    healthy: true,
    vms: 3,
    programsAttached: 0,
    programsTotal: 6,
    detections: 1,
    summary: 'observe: host traces only, guest tap attribution not attached',
  },
  vms: [
    { name: 'payment-prod-03', uuid: '8f3c2a10-1111-2222-3333-444455556666', runtime: 'kubevirt', hypervisor: 'node-07', pid: 19321, taps: ['tap7'], comm: 'qemu-system-x86_64', threadInfo: [{ tid: 19321, comm: 'qemu-system-x86', role: 'other' }, { tid: 19322, comm: 'CPU 0/KVM', role: 'vcpu' }, { tid: 19323, comm: 'IO iothread1', role: 'iothread' }, { tid: 19324, comm: 'vhost-19321', role: 'vhost' }] },
    { name: 'api-01', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'libvirt', hypervisor: 'node-07', pid: 20100, taps: ['tap1'], comm: 'qemu-system-x86_64' },
    { name: 'redis-01', uuid: 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'qemu', hypervisor: 'node-07', pid: 21010, taps: ['tap2'], comm: 'qemu-system-x86_64' },
  ],
  programs: [
    { name: 'kvm', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'sched', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'block', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'net', status: 'detached', detail: 'Fixture. Host TCP only. Not guest traffic.' },
    { name: 'tap', status: 'detached', detail: 'Fixture. No VM tap is attached.' },
    { name: 'drops', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
  ],
  kvm: [{ vm: 'payment-prod-03', runtime: 'kubevirt', exits: 182000, entries: 181200, mmio: 420, pio: 12, measured: true, topReasons: [{ reason: 30, count: 90000, totalNs: 4200000000, name: 'io_instruction' }, { reason: 12, count: 40000, totalNs: 91000000000, name: 'hlt' }], topReasonsByTime: [{ reason: 12, count: 40000, totalNs: 91000000000, name: 'hlt' }, { reason: 30, count: 90000, totalNs: 4200000000, name: 'io_instruction' }], exitLatencyP50Ns: 4096, exitLatencyP99Ns: 262144, exitLatencyHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9000, 61000, 70000, 30000, 9000, 2500, 400, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }],
  sched: [{ vm: 'payment-prod-03', onCpuNs: 870000000, wakeupDelayNs: 14000000, wakeupCount: 2200, wakeupDelayP50Ns: 4096, wakeupDelayP99Ns: 65536, vcpuPreemptedNs: 240000000, vcpuPreemptions: 31, topPreemptors: [{ who: 'vm:batch-etl-01', ns: 190000000 }, { who: 'kworker', ns: 50000000 }], wakeupHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 300, 700, 800, 260, 110, 24, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], measured: true }],
  schedThreads: [{ vm: 'payment-prod-03', tid: 19322, comm: 'CPU 0/KVM', role: 'vcpu', onCpuNs: 610000000, wakeupDelayNs: 9000000, wakeupCount: 1500, wakeupDelayP99Ns: 65536, preemptedNs: 240000000 }, { vm: 'payment-prod-03', tid: 19323, comm: 'IO iothread1', role: 'iothread', onCpuNs: 90000000, wakeupDelayNs: 4000000, wakeupCount: 700, wakeupDelayP99Ns: 32768 }],
  block: [{ vm: 'payment-prod-03', issues: 940, readP50Ns: 1200000, readP99Ns: 8400000, writeP50Ns: 3000000, writeP99Ns: 21000000, readMaxNs: 12000000, writeMaxNs: 28000000, readOps: 610, writeOps: 330, readBytes: 41943040, writeBytes: 25165824, readHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 210, 260, 70, 20, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], writeHist: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 60, 120, 90, 30, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], measured: true }],
  net: {
    attribution: 'qemu-process',
    guestAttributed: false,
    note: 'These are connects from the QEMU process, not the guest.',
    rows: [{ vm: 'payment-prod-03', connects: 183, retransmits: 19, attribution: 'qemu-process', guest_attributed: false, note: 'Connects and retransmits from the QEMU process, not the guest. Tap/TCX attribution is not attached.' }],
  },
  events: [
    { product: 'shukra', kind: 'exec', ts: '2026-09-19T09:42:01Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19321, comm: 'qemu-system-x86_64', message: 'QEMU thread exec' },
    { product: 'shukra', kind: 'tcp_connect', ts: '2026-09-19T09:42:03Z', vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, pid: 19321, dst: '185.1.2.3', dport: 443 },
    { product: 'shukra', kind: 'detection', ts: now, vm: { name: 'payment-prod-03', runtime: 'kubevirt' }, attribution: 'qemu-process', guest_attributed: false, dst: '185.1.2.3', dport: 443, severity: 'high', message: 'unexpected-egress destination 185.1.2.3' },
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
  if (url.pathname === '/api/v1/trace/drops') return { measured: false, rows: [], taps: [] };
  if (url.pathname === '/api/v1/trace/tap') return { rows: [] };
  if (url.pathname === '/api/v1/security') {
    return { vm: vm || '', detections: fixture.events.filter((e) => e.kind === 'detection'), enforcement: 'not_attached', allowList: [], durable: false, reason: 'Fixture. No management allow list is configured, so isolate would be refused.' };
  }
  if ((url.pathname === '/api/v1/isolate' || url.pathname === '/api/v1/release') && init?.method === 'POST') {
    const action = url.pathname.endsWith('release') ? 'release' : 'isolate';
    return { vm: 'payment-prod-03', enforcement: 'not_attached', applied: false, reason: 'Fixture. Nothing was enforced.', audit: { action, result: 'refused' } };
  }
  if (url.pathname === '/api/v1/trace/net') return { ...fixture.net, rows: filter(fixture.net.rows, vm) };
  if (url.pathname === '/api/v1/events') return { events: filterEvents(vm) };
  if (url.pathname === '/api/v1/detections' || url.pathname === '/api/v1/security') {
    const detections = fixture.events.filter((e) => e.kind === 'detection' && (!vm || e.vm.name === vm));
    return { vm, detections, enforcement: 'not_attached' };
  }
  if (url.pathname === '/api/v1/recorder') {
    return { window: url.searchParams.get('window') || '60s', events: filterEvents(vm) };
  }
  if (url.pathname === '/api/v1/explain') {
    return {
      vm: fixture.vms.find((v) => v.name === vm) || { name: vm || '', runtime: '' },
      question: 'why is this VM slow?',
      window: '1m0s',
      basis: 'Latencies are since the daemon attached, from log2 buckets, so each can read up to 2x high. They are the QEMU process\'s, not the guest\'s.',
      findings: [
        { cause: 'storage_latency', confidence: 'high', summary: 'Block requests from QEMU take long. Look at the backing device, its queue depth and other writers.', evidence: ['Block write p99 is up to 33.6 ms (slowest 28 ms) across 940 requests.'] },
        { cause: 'host_cpu_contention', confidence: 'medium', summary: "The VM's threads wait for a host CPU after being woken. Look at host CPU load, pinning and noisy neighbours.", evidence: ['Run-queue delay p99 is up to 2.1 ms on vCPU thread 19322 (CPU 0/KVM).'] },
      ],
      evidence: [
        'Identity comes from the QEMU command line, not from inside the guest.',
        'KVM exit counters are present for this thread group.',
        'TCP connects are from the QEMU process. They are not guest flows.',
      ],
      missing: [
        'guest tap attribution (TC/TCX on the VM tap is not attached)',
        'CPU steal as the guest counts it (Shukra measures the host\'s view: how long the vCPUs were preempted)',
        'in-guest process identity',
      ],
      events: filterEvents(vm),
    };
  }
  if (url.pathname === '/api/v1/isolate' && init?.method === 'POST') {
    return {
      vm: 'payment-prod-03',
      enforcement: 'not_attached',
      applied: false,
      reason: 'TC/TCX tap enforcement is not in this build. No program was attached.',
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
