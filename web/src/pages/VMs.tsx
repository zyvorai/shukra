import { LIVE_MS, useAPI } from '../useAPI';

type VM = {
  name: string;
  uuid?: string;
  runtime: string;
  hypervisor?: string;
  pid: number;
  taps?: string[];
  comm?: string;
  threadInfo?: { tid: number; comm?: string; role: string }[];
};

function roleLine(info?: { role: string }[]) {
  const n = { vcpu: 0, iothread: 0, vhost: 0, other: 0 };
  for (const t of info || []) {
    if (t.role === 'vcpu' || t.role === 'iothread' || t.role === 'vhost' || t.role === 'other') n[t.role] += 1;
  }
  return `vcpu ${n.vcpu} · iothread ${n.iothread} · vhost ${n.vhost} · other ${n.other}`;
}

export default function VMs() {
  const { data, err } = useAPI<{ vms: VM[] }>('/api/v1/vms', { refreshMs: LIVE_MS });
  const vms = data?.vms || [];
  if (err) return <p className="warning">{err}</p>;
  if (data && vms.length === 0) return <p className="empty-state">No qemu-system process in the proc scan.</p>;
  return (
    <div className="grid">
      {vms.map((vm) => (
        <section className="card span3" key={vm.name}>
          <p className="eyebrow">{vm.runtime}</p>
          <h3>{vm.name}</h3>
          <p>
            Hypervisor {vm.hypervisor || '—'} · PID {vm.pid} · {vm.comm} · taps {(vm.taps || []).join(', ') || '—'}
          </p>
          <p>{roleLine(vm.threadInfo)}</p>
          <p className="uuid">{vm.uuid}</p>
          <div className="metrics">
            <div><b>—</b><span>CPU steal · not measured</span></div>
            <div><b>—</b><span>guest tap flows · not measured</span></div>
            <div><b>—</b><span>in-guest processes · not measured</span></div>
          </div>
        </section>
      ))}
    </div>
  );
}
