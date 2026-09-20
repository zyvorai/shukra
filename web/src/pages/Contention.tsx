import { fmtNs } from '../hist';
import { LIVE_MS, useAPI } from '../useAPI';

type Pair = { victim: string; culprit: string; preemptedNs: number; share: number };
type Victim = { vm: string; preemptedNs: number; preemptions: number; byOtherVmsNs: number; bySelfNs: number; byHostNs: number; topHostTasks: { who: string; ns: number }[] };
type Culprit = { vm: string; tookNs: number; victims: number; onCpuNs: number; exits: number };
type Body = { note: string; window: string; pairs: Pair[]; victims: Victim[]; culprits: Culprit[] };

const dur = (n: number) => (n > 0 ? fmtNs(n) : '—');

/** A share, 0 to 1, as a whole percent. */
export const pct = (share: number) => `${Math.round(share * 100)}%`;

/** The named host tasks that took a VM's CPU, most first: "kworker 60 ms, cilium-agent 40 ms". */
export function hostTasks(v: Victim): string {
  return v.topHostTasks.length === 0 ? '—' : v.topHostTasks.map((t) => `${t.who} ${dur(t.ns)}`).join(', ');
}

function Table({ title, empty, cols, rows }: { title: string; empty: string; cols: string[]; rows: (string | number)[][] }) {
  return (
    <section className="card">
      <p className="eyebrow">CONTENTION</p>
      <h3>{title}</h3>
      {rows.length === 0 ? (
        <p className="empty-state">{empty}</p>
      ) : (
        <div className="investigation-table">
          <table>
            <thead>
              <tr>
                {cols.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  {r.map((cell, j) => (
                    <td key={j}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default function Contention() {
  const { data, err } = useAPI<Body>('/api/v1/trace/contention', { refreshMs: LIVE_MS });
  const window = data ? (data.window === 'lifetime' ? 'since the daemon attached' : `last ${data.window}`) : '…';
  return (
    <div>
      {err && <p className="warning">{err}</p>}
      <Table
        title={`Whose CPU another VM took (${window})`}
        empty="No VM took another VM's CPU in this window."
        cols={['victim', 'taken by VM', 'time', 'share of its preemption']}
        rows={(data?.pairs ?? []).map((p) => [p.victim, p.culprit, dur(p.preemptedNs), pct(p.share)])}
      />
      <Table
        title="Each VM's preemption, split by who took the CPU"
        empty="No VM has been measured by the sched program yet."
        cols={['vm', 'preempted', 'preemptions', 'by other VMs', 'by its own threads', 'by host tasks', 'top host tasks']}
        rows={(data?.victims ?? []).map((v) => [v.vm, dur(v.preemptedNs), v.preemptions, dur(v.byOtherVmsNs), dur(v.bySelfNs), dur(v.byHostNs), hostTasks(v)])}
      />
      <Table
        title="Culprits: what each VM was doing meanwhile"
        empty="No VM took another VM's CPU."
        cols={['vm', 'took', 'from VMs', 'its own on-cpu', 'its KVM exits']}
        rows={(data?.culprits ?? []).map((c) => [c.vm, dur(c.tookNs), c.victims, dur(c.onCpuNs), c.exits])}
      />
      <p className="hint">{data?.note ?? ''}</p>
    </div>
  );
}
