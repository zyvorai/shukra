import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import Policy, { byWaiting, needsConfirm, networks, removeText, tapLine, type PolicyRow } from './Policy';

const row: PolicyRow = { vm: 'web', mode: 'audit', allow: ['10.0.0.0/8'], source: 'manual', applied: '2026-09-20T03:00:00Z', present: true, taps: [] };

test('only a policy with a timer running waits to be confirmed', () => {
  expect(needsConfirm(row)).toBe(false);
  expect(needsConfirm({ ...row, revert: { until: '2026-09-20T03:10:00Z', to: 'no policy' } })).toBe(true);
});

test('what waits for a person is read first and the rest keep their order', () => {
  const wait = { until: 'x', to: 'no policy' };
  const list = [{ ...row, vm: 'a' }, { ...row, vm: 'b', revert: wait }, { ...row, vm: 'c' }, { ...row, vm: 'd', revert: wait }];
  expect(byWaiting(list).map((r) => r.vm)).toEqual(['b', 'd', 'a', 'c']);
});

test('a long list of networks is cut with the count of what is left, and an empty one says none', () => {
  expect(networks(['a', 'b'])).toBe('a, b');
  expect(networks(['a', 'b', 'c'])).toBe('a, b, c');
  expect(networks(['a', 'b', 'c', 'd', 'e'])).toBe('a, b, c and 2 more');
  expect(networks([])).toBe('none');
});

test('a tap says what its policy did, and leaves out what is zero', () => {
  const t = { tap: 'tap7', kernel: 'enforce', checked: 4210, auditPackets: 0, auditBytes: 0, droppedPackets: 14, droppedBytes: 1400 };
  expect(tapLine(t)).toBe('tap7: kernel enforce, judged 4210, 14 dropped');
  expect(tapLine({ ...t, kernel: 'audit', auditPackets: 7, droppedPackets: 0 })).toBe('tap7: kernel audit, judged 4210, 7 would have been dropped');
  expect(tapLine({ ...t, droppedPackets: 0 })).toBe('tap7: kernel enforce, judged 4210');
});

test('removing a policy is confirmed in words that name the VM and the consequence', () => {
  const t = removeText('web');
  expect(t).toContain("Remove web's egress policy?");
  expect(t).toContain('connect anywhere again');
});

test('on first paint the page shows no made-up policy', () => {
  const html = renderToStaticMarkup(<Policy />);
  expect(html).toContain('EGRESS POLICY');
  expect(html).not.toContain('payment-prod');
});
