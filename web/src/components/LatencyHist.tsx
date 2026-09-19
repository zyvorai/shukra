import { useState } from 'react';
import { bins, fmtCount, fmtNs, niceMax, yTicks } from '../hist';

// Mark specs: bars at most 24px thick, a 2px gap between them, a 4px rounded top
// and a square base on one baseline. One series, so no legend: the title says what
// is plotted. Text wears text tokens; only the bars are colored.
const SLOT = 26; // 24px bar + 2px gap
const PLOT_H = 120;
const PAD = { top: 10, right: 12, bottom: 30, left: 52 };
const LABEL_EVERY = 3; // an x label per 3 bars keeps them from touching

function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

export default function LatencyHist({ title, buckets, unit }: { title: string; buckets?: number[]; unit: string }) {
  const [active, setActive] = useState<number | null>(null);
  const data = bins(buckets);
  if (data.length === 0) return null;

  const top = niceMax(Math.max(...data.map((d) => d.count)));
  const width = Math.max(320, PAD.left + PAD.right + data.length * SLOT);
  const height = PAD.top + PLOT_H + PAD.bottom;
  const base = PAD.top + PLOT_H;
  const total = data.reduce((s, d) => s + d.count, 0);
  const label = (i: number) => `≤ ${fmtNs(data[i].hiNs)}: ${fmtCount(data[i].count)} ${unit} (${(data[i].share * 100).toFixed(1)}%)`;
  const tip = active === null ? null : data[active];
  const barH = (c: number) => (c === 0 ? 0 : Math.max(2, (c / top) * PLOT_H));

  return (
    <figure className="hist">
      <figcaption>
        <strong>{title}</strong>
        <span>
          {fmtCount(total)} {unit} · buckets are powers of two, so an edge can read up to 2x high
        </span>
      </figcaption>
      <div className="hist-plot" style={{ width }}>
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="group" aria-label={title} style={{ maxWidth: '100%', height: 'auto' }}>
          {yTicks(top).map((t) => {
            const y = base - (t / top) * PLOT_H;
            return (
              <g key={t}>
                <line className="hist-grid" x1={PAD.left} x2={width - PAD.right} y1={y} y2={y} />
                <text className="hist-tick" x={PAD.left - 8} y={y + 4} textAnchor="end">
                  {fmtCount(t)}
                </text>
              </g>
            );
          })}
          {data.map((d, i) => {
            const x = PAD.left + i * SLOT;
            const h = barH(d.count);
            return (
              <g key={d.index}>
                {h > 0 && <path className={active === i ? 'hist-bar is-active' : 'hist-bar'} d={topRounded(x + 1, base - h, SLOT - 2, h, 4)} />}
                {i % LABEL_EVERY === 0 && (
                  <text className="hist-tick" x={x + SLOT / 2} y={base + 18} textAnchor="middle">
                    {`≤ ${fmtNs(d.hiNs)}`}
                  </text>
                )}
                {/* The hit area is the whole column, not just the painted bar. */}
                <rect
                  className="hist-hit"
                  x={x}
                  y={PAD.top}
                  width={SLOT}
                  height={PLOT_H}
                  tabIndex={0}
                  role="img"
                  aria-label={label(i)}
                  onPointerEnter={() => setActive(i)}
                  onPointerLeave={() => setActive(null)}
                  onFocus={() => setActive(i)}
                  onBlur={() => setActive(null)}
                />
              </g>
            );
          })}
          <line className="hist-axis" x1={PAD.left} x2={width - PAD.right} y1={base} y2={base} />
        </svg>
        {tip && active !== null && (
          <div
            className="hist-tip"
            role="status"
            style={{ left: `${((PAD.left + active * SLOT + SLOT / 2) / width) * 100}%`, top: `${((base - barH(tip.count) - 6) / height) * 100}%` }}
          >
            <strong>{fmtCount(tip.count)}</strong>
            <span>
              {unit} · ≤ {fmtNs(tip.hiNs)} · {(tip.share * 100).toFixed(1)}%
            </span>
          </div>
        )}
      </div>
      <details className="hist-table">
        <summary>Show as table</summary>
        <table>
          <thead>
            <tr>
              <th>Latency</th>
              <th>{unit}</th>
              <th>Share</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.index}>
                <td>
                  {fmtNs(d.loNs)} – {fmtNs(d.hiNs)}
                </td>
                <td>{fmtCount(d.count)}</td>
                <td>{(d.share * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
