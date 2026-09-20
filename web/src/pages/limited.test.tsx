import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import { LimitedTrace } from './Traces';

const rows = Array.from({ length: 120 }, (_, i) => ({ ts: `2026-09-20T03:00:${String(i % 60).padStart(2, '0')}Z`, kind: 'tcp_connect', dst: `10.0.0.${i}`, dport: 443 }));

test('a long table shows 50 rows, states the total, and offers more', () => {
  const html = renderToStaticMarkup(<LimitedTrace title="Host connections" rows={rows} cols={['ts', 'dst']} filtered={false} />);
  expect(html).toContain('Host connections (120)');
  expect(html).toContain('Showing the newest 50 of 120.');
  expect(html).toContain('Show 50 more');
  expect((html.match(/<tr>/g) ?? []).length).toBe(51); // the header row and 50 events
});

test('a short table has no "show more"', () => {
  const html = renderToStaticMarkup(<LimitedTrace title="T" rows={rows.slice(0, 3)} cols={['dst']} filtered={false} />);
  expect(html).toContain('Showing the newest 3 of 3.');
  expect(html).not.toContain('more');
});

test('an empty table says whether it is the filter or nothing has happened', () => {
  expect(renderToStaticMarkup(<LimitedTrace title="T" rows={[]} cols={['dst']} filtered={true} />)).toContain('Nothing matches this filter.');
  const none = renderToStaticMarkup(<LimitedTrace title="T" rows={[]} cols={['dst']} filtered={false} />);
  expect(none).toContain('None seen yet.');
  expect(none).not.toContain('Programs may be detached');
});
