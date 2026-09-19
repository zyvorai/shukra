import HostBanner from '../components/HostBanner';
import { useAPI } from '../useAPI';

type Row = Record<string, unknown>;

function ns(v: unknown) {
  const n = Number(v);
  if (!Number.isFinite(n) || n === 0) return '—';
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} ms`;
  return `${n} ns`;
}

export function KVM() {
  const { data, err } = useAPI<{ rows: Row[] }>('/api/v1/trace/kvm');
  return <Trace title="KVM exits" err={err} rows={data?.rows} cols={['vm', 'exits', 'entries', 'mmio', 'pio']} />;
}

export function Sched() {
  const { data, err } = useAPI<{ rows: Row[] }>('/api/v1/trace/sched');
  return <Trace title="Scheduler" err={err} rows={data?.rows} cols={['vm', 'onCpuNs', 'wakeupDelayNs', 'wakeupCount']} format={{ onCpuNs: ns, wakeupDelayNs: ns }} />;
}

export function Block() {
  const { data, err } = useAPI<{ rows: Row[] }>('/api/v1/trace/block');
  return (
    <Trace
      title="Block latency"
      err={err}
      rows={data?.rows}
      cols={['vm', 'issues', 'readP50Ns', 'readP99Ns', 'writeP99Ns']}
      format={{ readP50Ns: ns, readP99Ns: ns, writeP99Ns: ns }}
    />
  );
}

export function Programs() {
  const { data, err } = useAPI<{ programs: Row[] }>('/api/v1/programs');
  return <Trace title="Programs" err={err} rows={data?.programs} cols={['name', 'status', 'detail']} />;
}

export function Connections() {
  const { data, err } = useAPI<{ events: Row[] }>('/api/v1/events');
  const rows = (data?.events || []).filter((e) => e.kind === 'tcp_connect' || e.kind === 'tcp_retransmit');
  return (
    <div>
      <HostBanner />
      <Trace title="Host connections" err={err} rows={rows} cols={['ts', 'kind', 'dst', 'dport', 'attribution', 'guest_attributed']} />
    </div>
  );
}

function Trace({
  title,
  err,
  rows,
  cols,
  format = {},
}: {
  title: string;
  err: string;
  rows?: Row[];
  cols: string[];
  format?: Record<string, (v: unknown) => string>;
}) {
  return (
    <section className="card">
      <p className="eyebrow">TRACE</p>
      <h3>{title}</h3>
      {err && <p className="warning">{err}</p>}
      {rows && rows.length === 0 && <p className="empty-state">No rows. Programs may be detached, and Shukra does not invent counters.</p>}
      {rows && rows.length > 0 && (
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
              {rows.map((row, i) => (
                <tr key={i}>
                  {cols.map((c) => (
                    <td key={c}>{format[c] ? format[c](row[c]) : String(row[c] ?? '—')}</td>
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
