import { useState } from 'react';
import { api } from '../api';
import { LIVE_MS, useAPI } from '../useAPI';

export type PolicyTap = { tap: string; kernel: string; checked: number; auditPackets: number; auditBytes: number; droppedPackets: number; droppedBytes: number };
export type PolicyRow = {
  vm: string;
  mode: string;
  allow: string[];
  source: string;
  by?: string;
  applied: string;
  present: boolean;
  revert?: { until: string; to: string };
  taps: PolicyTap[];
  problem?: string;
};
export type Orphan = { vm: string; tap: string; mode: string };
type Body = { enabled: boolean; persisted: boolean; note: string; policies: PolicyRow[]; orphans: Orphan[] };

/** Only an enforcing policy that is waiting for a person can be confirmed. */
export const needsConfirm = (r: Pick<PolicyRow, 'revert'>) => Boolean(r.revert);

/** What waits for a person first, then the rest in the order the daemon listed them. */
export function byWaiting(rows: PolicyRow[]): PolicyRow[] {
  return [...rows].sort((a, b) => Number(needsConfirm(b)) - Number(needsConfirm(a)));
}

/** A short list of the networks, with how many more there are. */
export function networks(allow: string[], show = 3): string {
  if (allow.length <= show) return allow.join(', ') || 'none';
  return `${allow.slice(0, show).join(', ')} and ${allow.length - show} more`;
}

/** What a tap's policy has done, in words. A count that is zero is not worth saying. */
export function tapLine(t: PolicyTap): string {
  const parts = [`kernel ${t.kernel}`, `judged ${t.checked}`];
  if (t.auditPackets > 0) parts.push(`${t.auditPackets} would have been dropped`);
  if (t.droppedPackets > 0) parts.push(`${t.droppedPackets} dropped`);
  return `${t.tap}: ${parts.join(', ')}`;
}

/** What to tell a person before a policy is lifted. */
export function removeText(vm: string): string {
  return `Remove ${vm}'s egress policy? Nothing is judged on its taps afterwards, so the VM may connect anywhere again.`;
}

export default function Policy() {
  const [tick, setTick] = useState(0);
  const { data, err } = useAPI<Body>(`/api/v1/policy?t=${tick}`, { refreshMs: LIVE_MS });
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');

  async function act(verb: 'confirm' | 'remove', vm: string) {
    setBusy(true);
    setConfirming(null);
    try {
      await api(`/api/v1/policy/${verb}`, { method: 'POST', body: JSON.stringify({ vm }) });
      setResult(verb === 'confirm' ? `${vm}'s policy is confirmed: it stays.` : `${vm}'s policy is removed.`);
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
        <p className="eyebrow">EGRESS POLICY</p>
        <h3>Not available</h3>
        <p className="empty-state">This build has no egress policy engine.</p>
      </section>
    );
  }
  const rows = byWaiting(data?.policies ?? []);
  const waiting = rows.filter(needsConfirm).length;
  return (
    <div>
      {err && <p className="warning">{err}</p>}
      <section className="card">
        <p className="eyebrow">EGRESS POLICY</p>
        <h3>{data ? `${rows.length} VMs under a policy${waiting > 0 ? `, ${waiting} waiting to be confirmed` : ''}` : '…'}</h3>
        <p className="hint">
          Which networks a VM may start connections to. Audit reports what would be dropped and drops nothing. Enforcing goes back to what the VM had unless it is confirmed in time. A policy is proposed and applied with
          <code> shukractl policy</code>.
        </p>
        {data && !data.persisted && <p className="warning">Enforcing needs -data-dir so that the record survives a restart, so only audit is possible here.</p>}
        {result && (
          <p role="status" className="hint">
            {result}
          </p>
        )}
        {(data?.orphans ?? []).map((o) => (
          <p key={o.tap} className="warning">
            {o.vm} ({o.tap}) is {o.mode} a policy that nobody has a record of.{' '}
            <button type="button" disabled={busy} onClick={() => act('remove', o.vm)}>
              Remove it
            </button>
          </p>
        ))}
        {rows.length === 0 ? (
          <p className="empty-state">No VM has an egress policy. `shukractl policy learn &lt;vm&gt;` proposes one from what the VM has been seen to do.</p>
        ) : (
          <div className="investigation-table">
            <table>
              <thead>
                <tr>
                  {['vm', 'mode', 'networks', 'set by', 'taps', ''].map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.vm}>
                    <td>
                      {r.vm}
                      {!r.present && <span className="hint"> (not running)</span>}
                    </td>
                    <td>
                      {r.mode}
                      {r.revert && <div className="warning">unconfirmed: goes back to {r.revert.to} at {r.revert.until}</div>}
                    </td>
                    <td title={r.allow.join(', ')}>
                      {r.allow.length}: {networks(r.allow)}
                    </td>
                    <td>
                      {r.by ?? ''} ({r.source})
                    </td>
                    <td>
                      {r.taps.map((t) => (
                        <div key={t.tap}>{tapLine(t)}</div>
                      ))}
                      {r.problem && <div className="warning">{r.problem}</div>}
                    </td>
                    <td>
                      {needsConfirm(r) && (
                        <>
                          <button type="button" className="primary" disabled={busy} onClick={() => act('confirm', r.vm)}>
                            Confirm
                          </button>{' '}
                        </>
                      )}
                      <button type="button" disabled={busy} onClick={() => setConfirming(r.vm)}>
                        Remove…
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {confirming && (
          <div role="alertdialog" aria-label="Confirm removing a policy" className="confirm">
            <p>{removeText(confirming)}</p>
            <button type="button" className="primary" disabled={busy} onClick={() => act('remove', confirming)}>
              Remove the policy
            </button>{' '}
            <button type="button" onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
