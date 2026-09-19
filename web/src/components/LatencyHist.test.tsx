import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import LatencyHist from './LatencyHist';

function h(pairs: Record<number, number>): number[] {
  const a = new Array(64).fill(0);
  for (const [k, v] of Object.entries(pairs)) a[Number(k)] = v;
  return a;
}

const html = (props: Partial<Parameters<typeof LatencyHist>[0]> = {}) =>
  renderToStaticMarkup(<LatencyHist title="db · write latency" buckets={h({ 20: 40, 21: 200, 23: 5 })} unit="requests" {...props} />);

test('draws nothing when there is nothing to plot', () => {
  expect(html({ buckets: h({}) })).toBe('');
  expect(html({ buckets: undefined })).toBe('');
});

test('one bar per populated bucket and one keyboard-reachable hit area per column', () => {
  const out = html();
  // Buckets 19..24 are shown (20, 21, 23 populated, plus padding); 3 have counts.
  expect(out.match(/class="hist-bar"/g)).toHaveLength(3);
  expect(out.match(/class="hist-hit"/g)).toHaveLength(6);
  expect(out.match(/tabindex="0"/g)).toHaveLength(6);
});

test('every column says what it is without a pointer', () => {
  const out = html();
  // Bucket 20 tops out at 2^21 ns = 2.1 ms and holds 40; bucket 21 holds the 200.
  expect(out).toContain('aria-label="≤ 2.1 ms: 40 requests (16.3%)"');
  expect(out).toContain('aria-label="≤ 4.19 ms: 200 requests (81.6%)"');
  expect(out).toContain('aria-label="≤ 8.39 ms: 0 requests (0.0%)"'); // an empty column still reads
});

test('the same numbers are in a table, so nothing depends on hover', () => {
  const out = html();
  expect(out).toContain('<details class="hist-table">');
  expect(out).toContain('Show as table');
  expect(out).toContain('<td>200</td>');
  expect(out).toContain('81.6%'); // 200 of 245
});

test('a title from the API is text, never markup', () => {
  const out = html({ title: '<img src=x onerror=alert(1)> · read latency' });
  expect(out).not.toContain('<img');
  expect(out).toContain('&lt;img');
});

test('the bar color is a theme token, not a hard-coded value', () => {
  // Color lives in styles.css on .hist-bar. Nothing in the markup should override it.
  expect(html()).not.toMatch(/fill="#|style="[^"]*fill:/);
});

test('states what the buckets are, so nobody reads an edge as an exact latency', () => {
  expect(html()).toContain('powers of two');
});
