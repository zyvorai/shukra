import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, expect, test, vi } from 'vitest';
import HostBanner from '../components/HostBanner';
import Login from '../components/Login';
import VMInput from '../components/VMInput';
import Explain from './Explain';
import Overview from './Overview';
import Recorder from './Recorder';
import { Isolate } from './Security';
import { header } from './Traces';

afterEach(() => vi.unstubAllGlobals());

test('no page opens on a VM name that only exists in the fixtures', () => {
  for (const page of [<Explain key="e" />, <Recorder key="r" />, <Isolate key="i" />]) {
    expect(renderToStaticMarkup(page)).not.toContain('payment-prod-03');
  }
});

test('a VM field suggests the VMs the daemon knows about', () => {
  const html = renderToStaticMarkup(<VMInput value="" names={['web-01', 'db-01']} onChange={() => {}} label="VM" />);
  expect(html).toContain('<option value="web-01"');
  expect(html).toContain('<option value="db-01"');
  expect(html).toContain('placeholder="VM name"');
});

test('the sign-in page names the daemon it is talking to, not loopback', () => {
  vi.stubGlobal('window', { location: { host: '80.79.5.173:30970' } });
  const html = renderToStaticMarkup(<Login onLogin={() => {}} />);
  expect(html).toContain('80.79.5.173:30970');
  expect(html).not.toContain('127.0.0.1:30970');
});

test('the host connections banner does not say the tap program is missing', () => {
  const html = renderToStaticMarkup(<HostBanner />);
  expect(html).toContain('guest_attributed is false');
  expect(html).not.toContain('not attached.');
});

test('the overview does not claim tap flows are unmeasured until it knows the tap is off', () => {
  const html = renderToStaticMarkup(<Overview />);
  expect(html).not.toContain('until tap/TCX ships');
  expect(html).not.toContain('Guest tap flows are not measured');
  expect(html).not.toContain('Guest traffic is not measured'); // nothing is known yet on first paint
});

test('the isolate page does not describe isolate as recording an audit row', () => {
  expect(renderToStaticMarkup(<Isolate />)).not.toContain('audit row');
});

test('a duration shown with its unit does not keep the Ns in its title', () => {
  expect(header('onCpuNs', true)).toBe('on Cpu');
  expect(header('wakeupDelayP99Ns', true)).toBe('wakeup Delay P99');
  expect(header('onCpuNs', false)).toBe('on Cpu Ns'); // a raw number is still in nanoseconds
  expect(header('vcpuPreemptions', false)).toBe('vcpu Preemptions');
});
