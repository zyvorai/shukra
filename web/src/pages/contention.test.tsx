import { renderToStaticMarkup } from 'react-dom/server';
import { expect, test } from 'vitest';
import Contention, { hostTasks, pct } from './Contention';

test('a share is a whole percent', () => {
  expect(pct(0)).toBe('0%');
  expect(pct(0.8)).toBe('80%');
  expect(pct(0.666)).toBe('67%');
  expect(pct(1)).toBe('100%');
});

test('host tasks are listed most first with their time, and none is a dash', () => {
  const v = { vm: 'a', preemptedNs: 0, preemptions: 0, byOtherVmsNs: 0, bySelfNs: 0, byHostNs: 0 };
  expect(hostTasks({ ...v, topHostTasks: [] })).toBe('—');
  expect(hostTasks({ ...v, topHostTasks: [{ who: 'kworker', ns: 60_000_000 }, { who: 'cilium-agent', ns: 40_000_000 }] })).toBe('kworker 60 ms, cilium-agent 40 ms');
});

test('the page says what an empty result means instead of showing nothing', () => {
  const html = renderToStaticMarkup(<Contention />);
  expect(html).toContain("No VM took another VM&#x27;s CPU in this window.");
  expect(html).toContain('No VM has been measured by the sched program yet.');
  expect(html).not.toContain('Programs may be detached');
});
