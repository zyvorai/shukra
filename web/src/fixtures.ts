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
    programsTotal: 4,
    detections: 1,
    summary: 'observe: host traces only, guest tap attribution not attached',
  },
  vms: [
    { name: 'payment-prod-03', uuid: '8f3c2a10-1111-2222-3333-444455556666', runtime: 'kubevirt', hypervisor: 'node-07', pid: 19321, taps: ['tap7'], comm: 'qemu-system-x86_64' },
    { name: 'api-01', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'libvirt', hypervisor: 'node-07', pid: 20100, taps: ['tap1'], comm: 'qemu-system-x86_64' },
    { name: 'redis-01', uuid: 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', runtime: 'qemu', hypervisor: 'node-07', pid: 21010, taps: ['tap2'], comm: 'qemu-system-x86_64' },
  ],
  programs: [
    { name: 'kvm', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'sched', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'block', status: 'detached', detail: 'Fixture. No BPF program is attached.' },
    { name: 'net', status: 'detached', detail: 'Fixture. Host TCP only. Not guest traffic.' },
  ],
  kvm: [{ vm: 'payment-prod-03', runtime: 'kubevirt', exits: 182000, entries: 181200, mmio: 420, pio: 12, measured: true, topReasons: [{ reason: 30, count: 90000 }, { reason: 12, count: 40000 }] }],
  sched: [{ vm: 'payment-prod-03', onCpuNs: 870000000, wakeupDelayNs: 14000000, wakeupCount: 2200, measured: true }],
  block: [{ vm: 'payment-prod-03', issues: 940, readP50Ns: 1200000, readP99Ns: 8400000, writeP50Ns: 3000000, writeP99Ns: 21000000, readMaxNs: 12000000, writeMaxNs: 28000000, measured: true }],
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
  if (url.pathname === '/api/v1/trace/sched') return { rows: filter(fixture.sched, vm) };
  if (url.pathname === '/api/v1/trace/block') return { rows: filter(fixture.block, vm) };
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
      evidence: [
        'Identity comes from the QEMU command line, not from inside the guest.',
        'KVM exit counters are present for this thread group.',
        'TCP connects are from the QEMU process. They are not guest flows.',
      ],
      missing: [
        'guest tap attribution (TC/TCX on the VM tap is not attached)',
        'CPU steal',
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
