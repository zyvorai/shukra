import { useState } from 'react';
import { LIVE_MS, useAPI } from '../useAPI';

type Det = { severity?: string; dst?: string; message?: string; guest_attributed: boolean; ts: string };

export function Detections() {
  const { data, err } = useAPI<{ detections: Det[] }>('/api/v1/detections', { refreshMs: LIVE_MS });
  return (
    <section className="card">
      <p className="eyebrow">WATCHLIST</p>
      <h3>Destination detections</h3>
      <p>Userspace match against the configured CIDRs. Nothing was blocked.</p>
      {err && <p className="warning">{err}</p>}
      {(data?.detections || []).length === 0 && <p className="empty-state">No detections.</p>}
      <ul className="detections">
        {(data?.detections || []).map((d) => (
          <li key={d.ts + d.dst}>
            <span className={`severity-badge ${d.severity || 'info'}`}>{d.severity || 'info'}</span>
            {d.dst} {d.message} · guest_attributed={String(d.guest_attributed)}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Isolate() {
  const [vm, setVM] = useState('payment-prod-03');
  return (
    <section className="card">
      <p className="eyebrow">ENFORCEMENT</p>
      <h3>Isolate is not attached</h3>
      <p>
        Recording a decision does not program TC, XDP, or Cilium. The apply control stays disabled until tap/TCX exists and an operator policy says management access stays open.
      </p>
      <div className="toolbar">
        <label>
          VM
          <input value={vm} onChange={(e) => setVM(e.target.value)} aria-label="VM to isolate" />
        </label>
        <button type="button" className="primary" disabled aria-describedby="isolate-why">
          Apply isolate
        </button>
      </div>
      <p id="isolate-why" className="warning">
        Apply is disabled. shukractl isolate {vm} records an audit row and leaves the datapath unchanged.
      </p>
    </section>
  );
}
