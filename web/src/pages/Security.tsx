import { useState } from 'react';
import { api } from '../api';
import { describeEnforcement, describeResult, type Isolation, type Security } from '../enforce';
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
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const { data } = useAPI<Security>('/api/v1/security', { refreshMs: LIVE_MS });
  const view = describeEnforcement(data);

  async function act(action: 'isolate' | 'release') {
    setBusy(true);
    setConfirming(false);
    try {
      const r = await api<Isolation>(`/api/v1/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vm }),
      });
      setResult(describeResult(r, action));
    } catch (e) {
      setResult({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <p className="eyebrow">ENFORCEMENT</p>
      <h3>{view.headline}</h3>
      <p>{view.detail}</p>
      <div className="toolbar">
        <label>
          VM
          <input value={vm} onChange={(e) => { setVM(e.target.value); setConfirming(false); setResult(null); }} aria-label="VM to isolate" />
        </label>
        <button type="button" className="primary" disabled={!view.canAct || busy || vm === ''} aria-describedby="isolate-why" onClick={() => setConfirming(true)}>
          Isolate…
        </button>
        <button type="button" disabled={!view.canAct || busy || vm === ''} onClick={() => act('release')}>
          Release
        </button>
      </div>
      {!view.canAct && (
        <p id="isolate-why" className="warning">
          The controls stay disabled until the daemon can enforce. shukractl isolate {vm} would only record an audit row.
        </p>
      )}
      {confirming && (
        <div className="confirm" role="alertdialog" aria-label={`Confirm isolating ${vm}`}>
          <p>
            <strong>Cut {vm} off from the network?</strong> Its tap will drop everything except ARP, IPv6 neighbour discovery and {view.allow.join(', ')}. It stays isolated until you release it, and the daemon re-applies it after a restart.
          </p>
          <button type="button" className="primary" onClick={() => act('isolate')}>
            Isolate {vm}
          </button>
          <button type="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      )}
      {result && (
        <p role="status" className={result.ok ? 'result-ok' : 'warning'}>
          {result.text}
        </p>
      )}
    </section>
  );
}
