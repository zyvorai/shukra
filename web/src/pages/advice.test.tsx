import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import Advice, { busy, byUrgency, halted, pct } from './Advice';

test('halted time is not claimed where this CPU does not name it, or where there is no window', () => {
  expect(halted({ idleAvailable: true, idleFraction: 0.94, window: '4m0s' })).toBe('94%');
  expect(halted({ idleAvailable: false, idleFraction: 0, window: '4m0s' })).toBe('n/a');
  expect(halted({ idleAvailable: true, idleFraction: 0.5, window: 'none' })).toBe('n/a');
});

test('busy is a percent and a count of vCPUs, or a dash without a window', () => {
  expect(busy({ busyFraction: 0.03, busyVcpus: 0.13, window: '4m0s' })).toBe('3% (0.1 vCPUs)');
  expect(busy({ busyFraction: 0, busyVcpus: 0, window: 'none' })).toBe('—');
  expect(pct(0.666)).toBe('67%');
});

test('advice is read most urgent first', () => {
  const k = (kind: string) => ({ kind, confidence: 'high', summary: '', evidence: [] });
  const sorted = ['no_change', 'not_enough_data', 'overprovisioned', 'starved', 'idle_unavailable', 'novel'].map(k).sort(byUrgency).map((a) => a.kind);
  expect(sorted).toEqual(['starved', 'overprovisioned', 'idle_unavailable', 'no_change', 'not_enough_data', 'novel']);
});

test('the page says so when there is no VM, and never shows a made-up one', () => {
  const html = renderToStaticMarkup(<Advice />);
  expect(html).toContain('No VM yet.');
  expect(html).not.toContain('payment-prod-03');
});
