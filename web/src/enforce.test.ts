import { expect, test } from 'vitest';
import { describeEnforcement, describeResult } from './enforce';

test('nothing may be done until the daemon has said it can enforce', () => {
  expect(describeEnforcement(null).canAct).toBe(false);
  const off = describeEnforcement({ enforcement: 'not_attached', reason: 'no management allow list is configured' });
  expect(off.canAct).toBe(false);
  expect(off.headline).toMatch(/not enforced/);
  expect(off.detail).toContain('allow list');
  // A missing reason still does not open the controls.
  expect(describeEnforcement({ enforcement: 'not_attached' }).canAct).toBe(false);
  expect(describeEnforcement({}).canAct).toBe(false);
  expect(describeEnforcement({ enforcement: 'something-new' }).canAct).toBe(false);
});

test('when enforcement is on, the page says exactly what stays reachable', () => {
  const on = describeEnforcement({ enforcement: 'tcx', allowList: ['10.0.0.1/32', 'fd99::1/128'] });
  expect(on.canAct).toBe(true);
  expect(on.detail).toContain('10.0.0.1/32, fd99::1/128');
  expect(on.detail).toContain('ARP');
  expect(on.allow).toHaveLength(2);
});

test('what happens when the daemon stops is said truthfully either way', () => {
  const durable = describeEnforcement({ enforcement: 'tcx', allowList: ['10.0.0.1/32'], durable: true });
  expect(durable.whenDaemonStops).toMatch(/stays isolated if the daemon stops or crashes/);
  expect(durable.whenDaemonStops).toContain('-detach-all');
  const fragile = describeEnforcement({ enforcement: 'tcx', allowList: ['10.0.0.1/32'], durable: false });
  expect(fragile.whenDaemonStops).toMatch(/reachable while the daemon is down/);
  expect(fragile.whenDaemonStops).not.toMatch(/stays isolated/);
  expect(describeEnforcement({ enforcement: 'not_attached' }).whenDaemonStops).toBe('');
});

test('a result is worded from what the daemon reported, never from what was asked', () => {
  const done = describeResult({ vm: 'db', enforcement: 'tcx', applied: true, taps: ['tap0'], reason: 'Traffic is dropped.' }, 'isolate');
  expect(done).toEqual({ ok: true, text: 'db isolated (tap0). Traffic is dropped.' });
  expect(describeResult({ vm: 'db', enforcement: 'tcx', applied: true, reason: 'Isolation lifted.' }, 'release').text).toContain('released');

  const refused = describeResult({ vm: 'db', enforcement: 'not_attached', applied: false, reason: 'no allow list', audit: { result: 'refused' } }, 'isolate');
  expect(refused.ok).toBe(false);
  expect(refused.text).toMatch(/^Refused\./);
  expect(refused.text).not.toMatch(/isolated/);

  const partial = describeResult({ vm: 'db', enforcement: 'tcx', applied: false, reason: 'isolated 1 of 2 taps', audit: { result: 'partial' } }, 'isolate');
  expect(partial.ok).toBe(false);
  expect(partial.text).toMatch(/^Only partly done\./);

  expect(describeResult({ vm: 'db', enforcement: 'not_attached', applied: false, reason: 'recorded only' }, 'isolate').text).toMatch(/^Not applied\./);
});
