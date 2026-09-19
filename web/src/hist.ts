// The daemon sends latency as log2 buckets (internal/hist): bucket i counts values
// below 2^(i+1) ns, and bucket 0 also holds 0 and 1. These helpers turn that into
// something a person can read. There is no DOM in here so it can be tested alone.

export type Bin = { index: number; loNs: number; hiNs: number; count: number; share: number };

const MAX_BUCKETS = 64;

/**
 * The populated part of a histogram, with one empty bucket either side so the
 * shape has context. Empty when nothing was counted: no chart beats a flat one.
 */
export function bins(buckets: number[] | undefined): Bin[] {
  if (!buckets || buckets.length === 0) return [];
  const n = Math.min(buckets.length, MAX_BUCKETS);
  let total = 0;
  let first = -1;
  let last = -1;
  for (let i = 0; i < n; i++) {
    const c = Number(buckets[i]);
    if (Number.isFinite(c) && c > 0) {
      total += c;
      if (first < 0) first = i;
      last = i;
    }
  }
  if (total === 0) return [];
  const out: Bin[] = [];
  for (let i = Math.max(0, first - 1); i <= Math.min(n - 1, last + 1); i++) {
    const c = Number(buckets[i]);
    const count = Number.isFinite(c) && c > 0 ? c : 0;
    out.push({ index: i, loNs: i === 0 ? 0 : 2 ** i, hiNs: 2 ** (i + 1), count, share: count / total });
  }
  return out;
}

function sig3(v: number): string {
  return String(Number(v.toPrecision(3)));
}

export function fmtNs(ns: number): string {
  if (!Number.isFinite(ns) || ns <= 0) return '0';
  if (ns < 1e3) return `${Math.round(ns)} ns`;
  if (ns < 1e6) return `${sig3(ns / 1e3)} µs`;
  if (ns < 1e9) return `${sig3(ns / 1e6)} ms`;
  return `${sig3(ns / 1e9)} s`;
}

export function fmtBytes(b: number): string {
  if (!Number.isFinite(b) || b <= 0) return '0';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = b;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${Math.round(v)} B` : `${sig3(v)} ${units[i]}`;
}

export function fmtCount(n: number): string {
  return Number.isFinite(n) ? n.toLocaleString('en-US') : '—';
}

/** Round up to 1, 2 or 5 times a power of ten, so axis ticks are clean numbers. */
export function niceMax(n: number): number {
  if (!Number.isFinite(n) || n <= 1) return 1;
  const p = 10 ** Math.floor(Math.log10(n));
  for (const m of [1, 2, 5, 10]) if (m * p >= n) return m * p;
  return 10 * p;
}

/** Y-axis ticks for 0..max: 0, the midpoint when it is a whole number, and max. */
export function yTicks(max: number): number[] {
  return max >= 4 && Number.isInteger(max / 2) ? [0, max / 2, max] : [0, max];
}
