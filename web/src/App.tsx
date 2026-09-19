import { useEffect, useState } from 'react';
import Nav, { type Page } from './components/Nav';
import PageHero, { type HeroTint } from './components/PageHero';
import Login from './components/Login';
import Overview from './pages/Overview';
import VMs from './pages/VMs';
import Recorder from './pages/Recorder';
import Explain from './pages/Explain';
import { Block, Connections, KVM, Programs, Sched } from './pages/Traces';
import { Detections, Isolate } from './pages/Security';
import { token, setToken } from './api';
import { applyTheme, readStoredTheme, toggleTheme, type Theme } from './theme';

const pages: Page[] = ['overview', 'vms', 'recorder', 'explain', 'kvm', 'sched', 'block', 'programs', 'connections', 'detections', 'isolate'];

function readPage(): Page {
  const m = window.location.hash.match(/page=([a-z]+)/);
  const id = m?.[1] as Page | undefined;
  return id && pages.includes(id) ? id : 'overview';
}

const heroes: Partial<Record<Page, { eyebrow: string; title: string; lede: string; tint?: HeroTint }>> = {
  vms: { eyebrow: 'Investigate', title: 'Know the virtual machine.', lede: 'Name, UUID, and tap names come from the QEMU command line.', tint: 'green' },
  recorder: { eyebrow: 'Investigate', title: 'Replay the last minute.', lede: 'A bounded ring per VM. Spikes, not every KVM exit.', tint: 'purple' },
  explain: { eyebrow: 'Investigate', title: 'Why is this VM slow?', lede: 'Only the evidence this build collected. Missing signals stay listed.', tint: 'amber' },
  kvm: { eyebrow: 'Diagnostics', title: 'KVM exits, counted.', lede: 'Exit counts, how long the host spends handling them, and which reasons cost the most. Not one event per exit.', tint: 'green' },
  sched: { eyebrow: 'Diagnostics', title: 'Scheduler delay.', lede: 'On-CPU time and run-queue delay for QEMU threads, and which thread is slow.', tint: 'amber' },
  block: { eyebrow: 'Diagnostics', title: 'Block latency.', lede: 'Requests, bytes, worst case and the latency distribution, from a log2 histogram on the QEMU I/O thread.', tint: 'amber' },
  programs: { eyebrow: 'Diagnostics', title: 'What is attached.', lede: 'kvm, sched, block, and net. Detached is an honest state.', tint: 'green' },
  connections: { eyebrow: 'Network', title: 'Host connections.', lede: 'tcp_v4_connect from the QEMU process. Not the guest.', tint: 'purple' },
  detections: { eyebrow: 'Security', title: 'New destinations.', lede: 'Watchlist hits. No packet was dropped.', tint: 'red' },
  isolate: { eyebrow: 'Security', title: 'Hold the VM.', lede: 'The decision is recorded. The datapath is not programmed.', tint: 'red' },
};

export default function App() {
  const [page, setPageState] = useState<Page>(readPage);
  const [loggedIn, setLoggedIn] = useState(() => Boolean(token()));
  const [authError, setAuthError] = useState('');
  const [theme, setTheme] = useState<Theme>(() => {
    const t = readStoredTheme();
    applyTheme(t);
    return t;
  });

  function setPage(p: Page) {
    window.location.hash = `page=${p}`;
    setPageState(p);
  }

  useEffect(() => {
    const onHash = () => setPageState(readPage());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    const onExpired = () => {
      setAuthError('The daemon rejected the API token.');
      setLoggedIn(false);
    };
    window.addEventListener('shukra-auth-expired', onExpired);
    return () => window.removeEventListener('shukra-auth-expired', onExpired);
  }, []);

  if (!loggedIn) {
    return <Login initialError={authError} onLogin={() => { setAuthError(''); setLoggedIn(true); }} />;
  }

  const body = {
    overview: <Overview />,
    vms: <VMs />,
    recorder: <Recorder />,
    explain: <Explain />,
    kvm: <KVM />,
    sched: <Sched />,
    block: <Block />,
    programs: <Programs />,
    connections: <Connections />,
    detections: <Detections />,
    isolate: <Isolate />,
  }[page];
  const hero = heroes[page];

  return (
    <>
      <Nav
        page={page}
        setPage={setPage}
        theme={theme}
        onToggleTheme={() => setTheme((t) => toggleTheme(t))}
        onLogout={() => {
          setToken('');
          setLoggedIn(false);
        }}
      />
      <main>
        <div key={page}>
          {page === 'overview' ? (
            <header className="hero">
              <div>
                <p className="eyebrow">SHUKRA · ZYVOR</p>
                <h1>Shukra.</h1>
                <p>eBPF-powered runtime intelligence and security for KVM. Observe, protect, and explain every workload from the host.</p>
              </div>
            </header>
          ) : (
            hero && <PageHero eyebrow={hero.eyebrow} title={hero.title} lede={hero.lede} tint={hero.tint} />
          )}
          {body}
        </div>
      </main>
    </>
  );
}
