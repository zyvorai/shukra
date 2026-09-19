import { expect, test } from 'vitest';
import { bins, fmtBytes, fmtCount, fmtNs, niceMax, yTicks } from './hist';

function h(pairs: Record<number, number>, len = 64): number[] {
  const a = new Array(len).fill(0);
  for (const [k, v] of Object.entries(pairs)) a[Number(k)] = v;
  return a;
}

test('bins keeps the populated range with one empty bucket of context on each side', () => {
  const b = bins(h({ 10: 5, 12: 15 }));
  expect(b.map((x) => x.index)).toEqual([9, 10, 11, 12, 13]);
  expect(b.map((x) => x.count)).toEqual([0, 5, 0, 15, 0]);
  expect(b.reduce((s, x) => s + x.share, 0)).toBeCloseTo(1);
  expect(b[1].share).toBeCloseTo(0.25);
});

test('a bucket covers [2^i, 2^(i+1)) ns, and bucket 0 starts at zero', () => {
  const b = bins(h({ 0: 1, 3: 1 }));
  expect(b[0]).toMatchObject({ index: 0, loNs: 0, hiNs: 2 });
  expect(b.find((x) => x.index === 3)).toMatchObject({ loNs: 8, hiNs: 16 });
});

test('the padding never runs off either end of the histogram', () => {
  expect(bins(h({ 0: 4 })).map((x) => x.index)).toEqual([0, 1]);
  expect(bins(h({ 63: 4 })).map((x) => x.index)).toEqual([62, 63]);
});

test('nothing counted means no bins, not a flat chart', () => {
  expect(bins(undefined)).toEqual([]);
  expect(bins([])).toEqual([]);
  expect(bins(h({}))).toEqual([]);
});

test('junk values are not counted and do not throw', () => {
  const junk = h({ 5: 3 }) as unknown as unknown[];
  junk[6] = 'x';
  junk[7] = NaN;
  junk[8] = -4;
  junk[9] = null;
  const b = bins(junk as number[]);
  expect(b.map((x) => x.count)).toEqual([0, 3, 0]);
});

test('more than 64 buckets are ignored rather than plotted', () => {
  const b = bins(h({ 10: 1, 70: 9 }, 80));
  expect(b.every((x) => x.index < 64)).toBe(true);
  expect(b.reduce((s, x) => s + x.count, 0)).toBe(1);
});

test('durations read at the right scale', () => {
  expect(fmtNs(0)).toBe('0');
  expect(fmtNs(NaN)).toBe('0');
  expect(fmtNs(999)).toBe('999 ns');
  expect(fmtNs(1000)).toBe('1 µs');
  expect(fmtNs(262144)).toBe('262 µs');
  expect(fmtNs(1048576)).toBe('1.05 ms');
  expect(fmtNs(21_000_000)).toBe('21 ms');
  expect(fmtNs(1e9)).toBe('1 s');
  expect(fmtNs(2 ** 40)).toBe('1100 s');
});

test('byte sizes and counts', () => {
  expect(fmtBytes(0)).toBe('0');
  expect(fmtBytes(512)).toBe('512 B');
  expect(fmtBytes(1024)).toBe('1 KiB');
  expect(fmtBytes(210395136)).toBe('201 MiB');
  expect(fmtCount(1234567)).toBe('1,234,567');
  expect(fmtCount(NaN)).toBe('—');
});

test('axis maximums are clean numbers that never clip the tallest bar', () => {
  for (const n of [1, 2, 3, 7, 9, 11, 42, 99, 101, 5000, 123456]) {
    const m = niceMax(n);
    expect(m).toBeGreaterThanOrEqual(n);
    expect(/^[125]0*$/.test(String(m))).toBe(true);
  }
  expect(niceMax(0)).toBe(1);
  expect(niceMax(NaN)).toBe(1);
  expect(yTicks(1)).toEqual([0, 1]);
  expect(yTicks(5)).toEqual([0, 5]); // no fractional midpoint
  expect(yTicks(20)).toEqual([0, 10, 20]);
});
