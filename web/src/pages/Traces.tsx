import HostBanner from '../components/HostBanner';
import LatencyHist from '../components/LatencyHist';
import { fmtBytes, fmtNs } from '../hist';
import { LIVE_MS, useAPI } from '../useAPI';

type Row = Record<string, unknown>;

function ns(v: unknown) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? fmtNs(n) : '—';
}

function bytes(v: unknown) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? fmtBytes(n) : '—';
}

function buckets(row: Row, key: string): number[] | undefined {
  const v = row[key];
  return Array.isArray(v) ? (v as number[]) : undefined;
}

// Reasons come with a name only where the daemon knows the numbering for this CPU.
function reasons(v: unknown) {
  if (!Array.isArray(v) || v.length === 0) return '—';
  return (v as Row[]).map((r) => `${r.name ?? '#' + String(r.reason)} ${ns(r.totalNs)}`).join(', ');
}

export function KVM() {
  const { data, err } = useAPI<{ rows: Row[] }>('/api/v1/trace/kvm', { refreshMs: LIVE_MS });
  return (
    <div>
      <Trace
        title="KVM exits"
        err={err}
        rows={data?.rows}
        cols={['vm', 'exits', 'entries', 'mmio', 'pio', 'exitLatencyP50Ns', 'exitLatencyP99Ns', 'topReasonsByTime']}
        format={{ exitLatencyP50Ns: ns, exitLatencyP99Ns: ns, topReasonsByTime: reasons }}
      >
        {(data?.rows || []).map((r) => (
          <LatencyHist key={String(r.vm)} title={`${String(r.vm)} · exit handling time`} buckets={buckets(r, 'exitLatencyHist')} unit="exits" />
        ))}
      </Trace>
    </div>
  );
}

export function Sched() {
  const { data, err } = useAPI<{ rows: Row[]; threads?: Row[] }>('/api/v1/trace/sched?threads=1', { refreshMs: LIVE_MS });
  return (
    <div>
      <Trace
        title="Scheduler"
        err={err}
        rows={data?.rows}
        cols={['vm', 'onCpuNs', 'wakeupDelayNs', 'wakeupCount', 'wakeupDelayP50Ns', 'wakeupDelayP99Ns', 'vcpuPreemptedNs', 'vcpuPreemptions', 'topPreemptors']}
        format={{
          onCpuNs: ns,
          wakeupDelayNs: ns,
          wakeupDelayP50Ns: ns,
          wakeupDelayP99Ns: ns,
          vcpuPreemptedNs: ns,
          topPreemptors: (v) => ((v as { who: string; ns: number }[] | undefined) || []).map((p) => `${p.who} ${ns(p.ns)}`).join(', ') || '—',
        }}
      >
        {(data?.rows || []).map((r) => (
          <LatencyHist key={String(r.vm)} title={`${String(r.vm)} · run-queue delay`} buckets={buckets(r, 'wakeupHist')} unit="wakeups" />
        ))}
      </Trace>
      {data?.threads && data.threads.length > 0 && (
        <Trace
          title="Threads"
          err=""
          rows={data.threads}
          cols={['vm', 'role', 'comm', 'tid', 'onCpuNs', 'wakeupCount', 'wakeupDelayP99Ns', 'preemptedNs']}
          format={{ onCpuNs: ns, wakeupDelayP99Ns: ns, preemptedNs: ns }}
        />
      )}
    </div>
  );
}

export function Block() {
  const { data, err } = useAPI<{ rows: Row[] }>('/api/v1/trace/block', { refreshMs: LIVE_MS });
  return (
    <Trace
      title="Block latency"
      err={err}
      rows={data?.rows}
      cols={['vm', 'readOps', 'writeOps', 'readBytes', 'writeBytes', 'readP50Ns', 'readP99Ns', 'readMaxNs', 'writeP99Ns', 'writeMaxNs']}
      format={{ readBytes: bytes, writeBytes: bytes, readP50Ns: ns, readP99Ns: ns, readMaxNs: ns, writeP99Ns: ns, writeMaxNs: ns }}
    >
      {(data?.rows || []).flatMap((r) => [
        <LatencyHist key={`${String(r.vm)}-r`} title={`${String(r.vm)} · read latency`} buckets={buckets(r, 'readHist')} unit="requests" />,
        <LatencyHist key={`${String(r.vm)}-w`} title={`${String(r.vm)} · write latency`} buckets={buckets(r, 'writeHist')} unit="requests" />,
      ])}
    </Trace>
  );
}

export function Drops() {
  const { data, err } = useAPI<{ measured: boolean; taps: Row[]; rows: Row[] }>('/api/v1/trace/drops', { refreshMs: LIVE_MS });
  if (data && !data.measured) {
    return (
      <section className="card">
        <p className="eyebrow">TRACE</p>
        <h3>Packets the kernel dropped on VM taps</h3>
        <p className="empty-state">The drops program is not measuring, so nothing can be said about drops. The Programs page says why. Shukra does not show a zero it did not measure.</p>
      </section>
    );
  }
  return (
    <>
      <Trace
        title="Packets the kernel dropped on VM taps"
        err={err}
        rows={data?.taps}
        cols={['vm', 'tap', 'kernelDrops', 'shukraDropped', 'otherDrops', 'guestNotReading']}
      />
      <Trace title="By reason" err="" rows={data?.rows} cols={['vm', 'tap', 'reason', 'count', 'location']} />
      <p className="hint">
        Shukra&apos;s own isolation drops show up as TC_INGRESS or TC_EGRESS, and are subtracted: <b>other drops</b> is what something else did. A full queue means the guest is not reading its NIC.
      </p>
    </>
  );
}

export function Programs() {
  const { data, err } = useAPI<{ programs: Row[] }>('/api/v1/programs', { refreshMs: LIVE_MS });
  return <Trace title="Programs" err={err} rows={data?.programs} cols={['name', 'status', 'detail']} />;
}

export function Connections() {
  const { data, err } = useAPI<{ events: Row[] }>('/api/v1/events', { refreshMs: LIVE_MS });
  const tap = useAPI<{ rows: Row[] }>('/api/v1/trace/tap', { refreshMs: LIVE_MS });
  const all = data?.events || [];
  const host = all.filter((e) => e.kind === 'tcp_connect' || e.kind === 'tcp_retransmit');
  const guest = all.filter((e) => e.kind === 'guest_connect' || e.kind === 'guest_flow' || e.kind === 'guest_inbound');
  const names = all.filter((e) => e.kind === 'guest_dns');
  return (
    <div>
      <HostBanner />
      <Trace title="Host connections" err={err} rows={host} cols={['ts', 'kind', 'dst', 'dport', 'attribution', 'guest_attributed']} />
      {guest.length > 0 && (
        <Trace
          title="Guest connections, connections into the guest, and UDP flows (seen on the VM tap)"
          err=""
          rows={guest}
          cols={['ts', 'vm', 'kind', 'proto', 'src', 'dst', 'dport', 'blocked', 'attribution', 'guest_attributed']}
          format={{ vm: (v) => String((v as { name?: string } | undefined)?.name ?? '—'), blocked: (v) => (v ? 'dropped' : '—') }}
        />
      )}
      {names.length > 0 && (
        <Trace
          title="Names the guest looked up (DNS over UDP port 53, seen on the VM tap)"
          err=""
          rows={names}
          cols={['ts', 'vm', 'dns_name', 'qtype', 'src', 'dst', 'blocked']}
          format={{ vm: (v) => String((v as { name?: string } | undefined)?.name ?? '—'), blocked: (v) => (v ? 'dropped' : '—') }}
        />
      )}
      {tap.data && tap.data.rows.length > 0 && (
        <Trace
          title="Guest TCP connections: what became of them (per tap)"
          err={tap.err}
          rows={tap.data.rows}
          cols={['vm', 'tap', 'outSyn', 'outAccepted', 'outRefused', 'outTimedOut', 'outBlocked', 'handshakeP50Ns', 'handshakeP99Ns', 'inSyn', 'inAccepted', 'inRefused', 'inIgnored']}
          format={{ handshakeP50Ns: ns, handshakeP99Ns: ns }}
        />
      )}
    </div>
  );
}

function Trace({
  title,
  err,
  rows,
  cols,
  format = {},
  children,
}: {
  title: string;
  err: string;
  rows?: Row[];
  cols: string[];
  format?: Record<string, (v: unknown) => string>;
  children?: React.ReactNode;
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
                  <th key={c}>{c.replace(/([a-z0-9])([A-Z])/g, '$1 $2')}</th>
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
      {children}
    </section>
  );
}
