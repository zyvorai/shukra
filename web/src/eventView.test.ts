import { expect, test } from 'vitest';
import { type Ev, hasText, inVM, newestFirst, NO_VM, page, PAGE, vmOf } from './eventView';

const web: Ev = { ts: '2026-09-20T03:00:02Z', kind: 'guest_connect', vm: { name: 'web-01' }, dst: '203.0.113.9', dport: 443 };
const db: Ev = { ts: '2026-09-20T03:00:01Z', kind: 'guest_dns', vm: { name: 'db-01' }, dns_name: 'Pool.Example.org', qtype: 'A' };
const tls: Ev = { ts: '2026-09-20T03:00:04Z', kind: 'guest_tls', vm: { name: 'web-01' }, sni: 'Api.Example.org', alpn: 'h2', ja3: '375c6162a492dfbf2795909110ce8424', dport: 443 };
const k3s: Ev = { ts: '2026-09-20T03:00:03Z', kind: 'tcp_connect', vm: {}, dst: '10.43.0.1', dport: 443, attribution: 'unattributed' };

test('a VM filter keeps that VM, and "host processes" keeps only events that belong to no VM', () => {
  const all = [web, db, k3s];
  expect(all.filter((e) => inVM(e, ''))).toHaveLength(3);
  expect(all.filter((e) => inVM(e, 'web-01'))).toEqual([web]);
  expect(all.filter((e) => inVM(e, NO_VM))).toEqual([k3s]);
  expect(all.filter((e) => inVM(e, 'nobody'))).toEqual([]);
  expect(vmOf({})).toBe('');
});

test('a search matches address, port, name and kind, ignoring case, and an empty search matches everything', () => {
  expect(hasText(web, '203.0.113')).toBe(true);
  expect(hasText(web, '443')).toBe(true);
  expect(hasText(db, 'pool.example')).toBe(true);
  expect(hasText(db, ' POOL ')).toBe(true);
  expect(hasText(web, 'guest_connect')).toBe(true);
  expect(hasText(tls, 'api.example')).toBe(true);
  expect(hasText(tls, 'H2')).toBe(true);
  expect(hasText(tls, '375c6162')).toBe(true);
  expect(hasText(web, 'nanopool')).toBe(false);
  expect(hasText(k3s, '')).toBe(true);
  expect(hasText(k3s, '   ')).toBe(true);
});

test('events are newest first and the input is not reordered', () => {
  const input = [web, db, k3s];
  expect(newestFirst(input).map((e) => e.kind)).toEqual(['tcp_connect', 'guest_connect', 'guest_dns']);
  expect(input[0]).toBe(web);
  expect(newestFirst([{ kind: 'x' }, web]).map((e) => e.kind)).toEqual(['guest_connect', 'x']); // no timestamp sorts last
});

test('paging says how many were cut off and never cuts silently', () => {
  const rows = Array.from({ length: 120 }, (_, i) => i);
  expect(page(rows, PAGE)).toEqual({ shown: rows.slice(0, 50), total: 120, more: 70 });
  expect(page(rows, 150)).toEqual({ shown: rows, total: 120, more: 0 });
  expect(page([], PAGE)).toEqual({ shown: [], total: 0, more: 0 });
  expect(page(rows, -5).shown).toEqual([]);
});
