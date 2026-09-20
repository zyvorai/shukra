import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import Actions, { byWaiting, canDecide, confirmText, outcome, type Act } from './Actions';

const base: Act = { id: 'a-1', vm: 'web', response: 'contain', mode: 'propose', rule: 'crypto-pool', severity: 'high', message: 'm', status: 'pending', created: '2026-09-20T03:00:00Z' };

test('only a proposal that is still waiting can be decided', () => {
  expect(canDecide({ status: 'pending' })).toBe(true);
  for (const s of ['executed', 'refused', 'rejected', 'expired', 'dry_run', 'released']) expect(canDecide({ status: s })).toBe(false);
});

test('what waits for a person is read first and the rest keep their order', () => {
  const list = [
    { ...base, id: 'a-4', status: 'executed' },
    { ...base, id: 'a-3', status: 'pending' },
    { ...base, id: 'a-2', status: 'refused' },
    { ...base, id: 'a-1', status: 'pending' },
  ];
  expect(byWaiting(list).map((a) => a.id)).toEqual(['a-3', 'a-1', 'a-4', 'a-2']);
});

test('the confirmation names the VM, the response and the consequence', () => {
  const t = confirmText(base);
  expect(t).toContain('Isolate web?');
  expect(t).toContain('"contain"');
  expect(t).toContain('crypto-pool');
  expect(t).toContain('until it is released');
});

test('an action reads as what it is waiting for or how it ended', () => {
  expect(outcome({ ...base, expires: '2026-09-20T03:30:00Z' })).toBe('waiting, lapses 2026-09-20T03:30:00Z');
  expect(outcome({ ...base, status: 'executed', result: 'isolated: 1 tap', decidedBy: 'alice', releaseAt: '2026-09-20T03:10:00Z' })).toBe(
    'isolated: 1 tap (alice) releases itself at 2026-09-20T03:10:00Z',
  );
  expect(outcome({ ...base, status: 'refused', result: 'web is protected' })).toBe('web is protected');
  expect(outcome({ ...base, status: 'expired' })).toBe('expired');
});

test('on first paint the page shows no made-up action', () => {
  const html = renderToStaticMarkup(<Actions />);
  expect(html).not.toContain('payment-prod-03');
  expect(html).toContain('Nothing has been proposed or done yet.');
});
