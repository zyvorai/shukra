import { useState } from 'react';
import { api } from '../api';
import { LIVE_MS, useAPI } from '../useAPI';

export type Act = {
  id: string;
  vm: string;
  response: string;
  mode: string;
  rule: string;
  severity: string;
  message: string;
  status: string;
  created: string;
  expires?: string;
  decidedBy?: string;
  result?: string;
  guardrail?: string;
  releaseAt?: string;
};
type Body = { enabled: boolean; pending: number; note: string; actions: Act[] };

/** Only a proposal that is still waiting can be approved or rejected. */
export const canDecide = (a: Pick<Act, 'status'>) => a.status === 'pending';

/** The order to read actions in: what waits for a person first, then the rest as the daemon listed them (newest first). */
export function byWaiting(list: Act[]): Act[] {
  return [...list].sort((a, b) => Number(canDecide(b)) - Number(canDecide(a)));
}

/** What to tell a person before an isolation, in words that name the VM and the consequence. */
export function confirmText(a: Pick<Act, 'vm' | 'rule' | 'response'>): string {
  return `Isolate ${a.vm}? Response "${a.response}" proposed it for ${a.rule}. Its tap will drop everything except ARP, IPv6 neighbour discovery and the management networks, until it is released.`;
}

/** A one-line reading of how an action ended, or what it is waiting for. */
export function outcome(a: Act): string {
  if (a.status === 'pending') return a.expires ? `waiting, lapses ${a.expires}` : 'waiting';
  const parts = [a.result ?? ''];
  if (a.decidedBy) parts.push(`(${a.decidedBy})`);
  if (a.status === 'executed' && a.releaseAt) parts.push(`releases itself at ${a.releaseAt}`);
  return parts.filter(Boolean).join(' ') || a.status;
}

export default function Actions() {
  const [tick, setTick] = useState(0);
  const { data, err } = useAPI<Body>(`/api/v1/actions?all=1&t=${tick}`, { refreshMs: LIVE_MS });
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');

  async function decide(id: string, verb: 'approve' | 'reject') {
    setBusy(true);
    setConfirming(null);
    try {
      await api(`/api/v1/actions/${encodeURIComponent(id)}/${verb}`, { method: 'POST' });
      setResult(verb === 'approve' ? `${id} approved: the VM is isolated.` : `${id} rejected: nothing was done.`);
    } catch (e) {
      setResult(String(e));
    } finally {
      setBusy(false);
      setTick((n) => n + 1);
    }
  }

  if (data && !data.enabled) {
    return (
      <section className="card">
        <p className="eyebrow">ACTIONS</p>
        <h3>Responses are off</h3>
        <p className="empty-state">The rules file has no responses section, so nothing is proposed or done automatically. See the rules example for how to add one.</p>
      </section>
    );
  }
  const rows = byWaiting(data?.actions ?? []);
  const asked = rows.find((r) => r.id === confirming);
  return (
    <div>
      {err && <p className="warning">{err}</p>}
      <section className="card">
        <p className="eyebrow">ACTIONS</p>
        <h3>{data ? `${data.pending} waiting for a decision` : '…'}</h3>
        {result && (
          <p role="status" className="hint">
            {result}
          </p>
        )}
        {rows.length === 0 ? (
          <p className="empty-state">Nothing has been proposed or done yet.</p>
        ) : (
          <div className="investigation-table">
            <table>
              <thead>
                <tr>
                  {['id', 'vm', 'response', 'for', 'status', 'what happened', ''].map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td>{a.id}</td>
                    <td>{a.vm}</td>
                    <td>
                      {a.response} ({a.mode})
                    </td>
                    <td>
                      {a.rule} [{a.severity}]<br />
                      {a.message}
                    </td>
                    <td>{a.status.replace(/_/g, ' ')}</td>
                    <td>{outcome(a)}</td>
                    <td>
                      {canDecide(a) && (
                        <>
                          <button type="button" className="primary" disabled={busy} onClick={() => setConfirming(a.id)}>
                            Approve…
                          </button>{' '}
                          <button type="button" disabled={busy} onClick={() => decide(a.id, 'reject')}>
                            Reject
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {asked && (
          <div className="confirm" role="alertdialog" aria-label={`Confirm isolating ${asked.vm}`}>
            <p>
              <strong>{confirmText(asked)}</strong>
            </p>
            <button type="button" className="primary" onClick={() => decide(asked.id, 'approve')}>
              Isolate {asked.vm}
            </button>{' '}
            <button type="button" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        )}
        <p className="hint">{data?.note ?? ''}</p>
      </section>
    </div>
  );
}
