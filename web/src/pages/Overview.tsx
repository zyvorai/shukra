import { fixtureMode } from '../fixtures';
import { LIVE_MS, useAPI } from '../useAPI';

type Status = {
  vms: number;
  programsAttached: number;
  programsTotal: number;
  detections: number;
  mode: string;
  summary: string;
};

export default function Overview() {
  const { data, err } = useAPI<Status>('/api/v1/status', { refreshMs: LIVE_MS });
  const programs = useAPI<{ programs: { name: string; status: string }[] }>('/api/v1/programs', { refreshMs: LIVE_MS });
  const tapKnown = Boolean(programs.data);
  const tapAttached = programs.data?.programs.some((p) => p.name === 'tap' && p.status === 'attached') ?? false;
  return (
    <div className="grid">
      {fixtureMode && <p className="warning span3">Fixture data. shukrad is not attached. Counters on the other pages are sample rows, not a live hypervisor.</p>}
      <section className="card span2">
        <p className="eyebrow">SHUKRA</p>
        <h3>No agent inside the VM.</h3>
        <p>Root is the hypervisor. Identity comes from the host: the QEMU command line, or FluxVM's store. Host connections are the VMM's own; the guest's are seen on its tap when the tap program is attached.</p>
        <div className="metrics">
          <div><b>{data?.vms ?? '—'}</b><span>virtual machines</span></div>
          <div><b>{data ? `${data.programsAttached}/${data.programsTotal}` : '—'}</b><span>programs attached</span></div>
          <div><b>{data?.detections ?? '—'}</b><span>detections</span></div>
          <div><b>{data?.mode ?? '—'}</b><span>mode</span></div>
        </div>
        {err && <p className="warning">{err}</p>}
      </section>
      <section className="card">
        <p className="eyebrow">BOUNDARY</p>
        <h3>What this build will not say</h3>
        <p className="missing">CPU steal as the guest counts it is not measured. The host&apos;s view of it, vCPU preemption, is on the Scheduler page.</p>
        {tapKnown && !tapAttached && <p className="missing">Guest traffic is not measured: the tap program is not attached to any VM.</p>}
        <p className="missing">In-guest process identity is not measured.</p>
        {data?.summary && <p>{data.summary}</p>}
      </section>
    </div>
  );
}
