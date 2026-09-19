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
  return (
    <div className="grid">
      {fixtureMode && <p className="warning span3">Fixture data. shukrad is not attached. Counters on the other pages are sample rows, not a live hypervisor.</p>}
      <section className="card span2">
        <p className="eyebrow">SHUKRA</p>
        <h3>No agent inside the VM.</h3>
        <p>Root is the hypervisor. Identity is the QEMU command line. Network events stay on the QEMU process until tap/TCX ships.</p>
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
        <p className="missing">Guest tap flows are not measured.</p>
        <p className="missing">In-guest process identity is not measured.</p>
        {data?.summary && <p>{data.summary}</p>}
      </section>
    </div>
  );
}
