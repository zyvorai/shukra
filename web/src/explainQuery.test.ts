import { expect, test } from 'vitest';
import { atFromInput, explainPath, incidentFileName, incidentPath } from './explainQuery';

test('a past time is sent as UTC, and blank means now', () => {
  expect(atFromInput('')).toBe('');
  expect(atFromInput('not a time')).toBe('');
  const iso = atFromInput('2026-09-20T03:12');
  expect(iso).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/);
  expect(new Date(iso).getTime()).toBe(new Date('2026-09-20T03:12').getTime());
});

test('the explain and incident paths carry the VM, the window and, only when set, the time', () => {
  expect(explainPath('web-01', '60s', '')).toBe('/api/v1/explain?vm=web-01&window=60s');
  expect(explainPath('web 01', '15m', '2026-09-20T03:12:00.000Z')).toBe('/api/v1/explain?vm=web+01&window=15m&at=2026-09-20T03%3A12%3A00.000Z');
  expect(incidentPath('db', '1h', '')).toBe('/api/v1/incident?vm=db&window=1h');
  expect(incidentPath('db', '1h', '2026-09-20T03:12:00.000Z')).toContain('at=2026-09-20T03%3A12%3A00.000Z');
});

test('a downloaded bundle gets a file name that is safe anywhere', () => {
  expect(incidentFileName('web-01', '')).toBe('shukra-incident-web-01-now.json');
  expect(incidentFileName('a/b\\c:d', '2026-09-20T03:12:00.000Z')).toBe('shukra-incident-a_b_c_d-2026-09-20T03_12_00.000Z.json');
  expect(incidentFileName('', '')).toBe('shukra-incident-vm-now.json');
});
