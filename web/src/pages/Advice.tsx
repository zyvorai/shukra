import { fmtNs } from '../hist';
import { LIVE_MS, useAPI } from '../useAPI';

type AdviceItem = { kind: string; confidence: string; summary: string; evidence: string[] };
type Row = {
  vm: string;
  vcpus: number;
  window: string;
  idleAvailable: boolean;
  idleFraction: number;
  busyFraction: number;
  busyVcpus: number;
  preemptShare: number;
  unaccountedFraction: number;
  runqueueDelayP99Ns: number;
  advice: AdviceItem[];
};
type Body = { note: string; window: string; rows: Row[] };

/** A share, 0 to 1, as a whole percent. */
export const pct = (share: number) => `${Math.round(share * 100)}%`;

/** Halted time as a percent, or "n/a" where this CPU does not name the halt exit (nothing is claimed then). */
export function halted(r: Pick<Row, 'idleAvailable' | 'idleFraction' | 'window'>): string {
  return r.window === 'none' || !r.idleAvailable ? 'n/a' : pct(r.idleFraction);
}

/** On-CPU time as a percent and in vCPUs, or a dash for a VM with no window to measure. */
export function busy(r: Pick<Row, 'busyFraction' | 'busyVcpus' | 'window'>): string {
  return r.window === 'none' ? '—' : `${pct(r.busyFraction)} (${r.busyVcpus.toFixed(1)} vCPUs)`;
}

/** The order to read advice in: what needs action first. */
const rank: Record<string, number> = { starved: 0, overprovisioned: 1, nearly_idle: 2, idle_unavailable: 3, no_change: 4, not_enough_data: 5 };
export const byUrgency = (a: AdviceItem, b: AdviceItem) => (rank[a.kind] ?? 9) - (rank[b.kind] ?? 9);

export default function Advice() {
  const { data, err } = useAPI<Body>('/api/v1/advice', { refreshMs: LIVE_MS });
  const rows = data?.rows ?? [];
  return (
    <div>
      {err && <p className="warning">{err}</p>}
      <section className="card">
        <p className="eyebrow">RIGHT-SIZE</p>
        <h3>Is each VM the right size? ({data ? `last ${data.window}` : '…'})</h3>
        {rows.length === 0 ? (
          <p className="empty-state">No VM yet.</p>
        ) : (
          <div className="investigation-table">
            <table>
              <thead>
                <tr>
                  {['vm', 'vCPUs', 'halted', 'busy', 'preempted', 'neither', 'worst run-queue wait', 'advice'].map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.vm}>
                    <td>{r.vm}</td>
                    <td>{r.vcpus}</td>
                    <td>{halted(r)}</td>
                    <td>{busy(r)}</td>
                    <td>{r.window === 'none' ? '—' : pct(r.preemptShare)}</td>
                    <td>{r.window === 'none' || !r.idleAvailable ? '—' : pct(r.unaccountedFraction)}</td>
                    <td>{r.runqueueDelayP99Ns > 0 ? fmtNs(r.runqueueDelayP99Ns) : '—'}</td>
                    <td>
                      {[...r.advice].sort(byUrgency).map((a) => (
                        <p key={a.kind}>
                          <strong>{a.kind.replace(/_/g, ' ')}</strong> <span className={`severity-badge conf-${a.confidence}`}>{a.confidence}</span> {a.summary}
                          {a.evidence.map((e) => (
                            <span key={e} className="finding-evidence">
                              {' '}
                              {e}
                            </span>
                          ))}
                        </p>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="hint">{data?.note ?? ''}</p>
      </section>
    </div>
  );
}
