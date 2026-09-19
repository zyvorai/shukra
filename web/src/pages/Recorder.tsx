import { useState } from 'react';
import { useAPI } from '../useAPI';

type Ev = { ts: string; kind: string; message?: string; dst?: string; attribution: string; guest_attributed: boolean };

export default function Recorder() {
  const [vm, setVM] = useState('payment-prod-03');
  const [windowed, setWindowed] = useState(true);
  const { data, err } = useAPI<{ window: string; events: Ev[] }>(`/api/v1/recorder?vm=${encodeURIComponent(vm)}&window=${windowed ? '60s' : '24h'}`);
  return (
    <div>
      <div className="toolbar">
        <label>
          VM
          <input value={vm} onChange={(e) => setVM(e.target.value)} aria-label="VM name" />
        </label>
        <button type="button" className="primary" onClick={() => setWindowed(true)}>
          Replay last 60 seconds
        </button>
        <button type="button" onClick={() => setWindowed(false)}>
          Full ring
        </button>
      </div>
      {err && <p className="warning">{err}</p>}
      <section className="card">
        <p className="eyebrow">FLIGHT RECORDER</p>
        <h3>{windowed ? '60s' : `Full ring · ${(data?.events || []).length} events`}</h3>
        {(data?.events || []).length === 0 && <p className="empty-state">No events in this window.</p>}
        <ol className="timeline">
          {(data?.events || []).map((e, i) => (
            <li key={e.ts + e.kind + i}>
              <time>{e.ts}</time>
              <strong>{e.kind}</strong>
              <span>{e.message || e.dst || e.attribution}</span>
              <em>guest_attributed={String(e.guest_attributed)}</em>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
