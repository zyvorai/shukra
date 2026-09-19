import { useEffect, useRef, useState } from 'react';
import type { Theme } from '../theme';

export type Page =
  | 'overview'
  | 'vms'
  | 'recorder'
  | 'explain'
  | 'kvm'
  | 'sched'
  | 'block'
  | 'programs'
  | 'connections'
  | 'drops'
  | 'detections'
  | 'isolate';

type NavLink = { page: Page; label: string; blurb: string };
type NavGroup = { label: string; page?: Page; children?: NavLink[] };

const groups: NavGroup[] = [
  { label: 'Overview', page: 'overview' },
  {
    label: 'Investigate',
    children: [
      { page: 'vms', label: 'Virtual machines', blurb: 'QEMU identity from the host command line. Not an agent inside the guest.' },
      { page: 'recorder', label: 'Flight recorder', blurb: 'Bounded per-VM history. Replay the last 60 seconds.' },
      { page: 'explain', label: 'Explain', blurb: 'Why this VM looks slow, from the counters we actually have.' },
    ],
  },
  {
    label: 'Diagnostics',
    children: [
      { page: 'kvm', label: 'KVM', blurb: 'Exit, entry, MMIO, and PIO counters per QEMU thread group.' },
      { page: 'sched', label: 'Scheduler', blurb: 'On-CPU time and wakeup delay for those threads.' },
      { page: 'block', label: 'Block', blurb: 'Log2 latency histogram for the QEMU I/O thread.' },
      { page: 'programs', label: 'Programs', blurb: 'Attached, detached, or missing. A missing KVM module does not stop the others.' },
    ],
  },
  {
    label: 'Network',
    children: [
      { page: 'connections', label: 'Host connections', blurb: 'tcp_v4_connect from the QEMU process. Not guest traffic.' },
      { page: 'drops', label: 'Drops', blurb: 'Packets the kernel dropped on VM taps, and whether Shukra dropped them.' },
    ],
  },
  {
    label: 'Security',
    children: [
      { page: 'detections', label: 'Detections', blurb: 'Destination watchlist hits. Userspace only.' },
      { page: 'isolate', label: 'Isolate', blurb: 'Record a decision. Enforcement is not attached in this build.' },
    ],
  },
];

const OPEN_DELAY_MS = 120;
const CLOSE_DELAY_MS = 450;

export default function Nav({
  page,
  setPage,
  theme,
  onToggleTheme,
  onLogout,
}: {
  page: Page;
  setPage: (p: Page) => void;
  theme: Theme;
  onToggleTheme: () => void;
  onLogout: () => void;
}) {
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const openTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const navRef = useRef<HTMLElement | null>(null);

  const clearTimers = () => {
    if (openTimer.current) clearTimeout(openTimer.current);
    if (closeTimer.current) clearTimeout(closeTimer.current);
  };
  const scheduleOpen = (label: string) => {
    clearTimers();
    openTimer.current = setTimeout(() => setOpenGroup(label), OPEN_DELAY_MS);
  };
  const scheduleClose = () => {
    clearTimers();
    closeTimer.current = setTimeout(() => setOpenGroup(null), CLOSE_DELAY_MS);
  };

  useEffect(() => () => clearTimers(), []);
  useEffect(() => {
    if (!openGroup) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpenGroup(null);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [openGroup]);

  return (
    <nav className="nav" aria-label="Global" ref={navRef}>
      <div className="nav-inner">
        <button type="button" className="brand" onClick={() => setPage('overview')} aria-label="Shukra home">
          <img src="/zyvor-mark.svg" alt="" className="brand-mark" />
          Shukra
        </button>
        <div className="navlinks">
          {groups.map((g) =>
            g.children ? (
              <div key={g.label} className="navgroup" onMouseEnter={() => scheduleOpen(g.label)} onMouseLeave={scheduleClose}>
                <button
                  type="button"
                  className={g.children.some((c) => c.page === page) ? 'active' : ''}
                  aria-haspopup="true"
                  aria-expanded={openGroup === g.label}
                  onClick={() => setOpenGroup((cur) => (cur === g.label ? null : g.label))}
                >
                  {g.label}
                </button>
                <div className={`mega-panel${openGroup === g.label ? ' open' : ''}`} role="region" aria-label={g.label}>
                  <div className="mega-grid">
                    {g.children.map((c) => (
                      <button
                        key={c.page}
                        type="button"
                        className={page === c.page ? 'active' : ''}
                        aria-current={page === c.page ? 'page' : undefined}
                        onClick={() => {
                          setPage(c.page);
                          setOpenGroup(null);
                        }}
                      >
                        <span className="mega-link-label">{c.label}</span>
                        <span className="mega-link-blurb">{c.blurb}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <button key={g.page} type="button" className={page === g.page ? 'active' : ''} onClick={() => setPage(g.page as Page)}>
                {g.label}
              </button>
            ),
          )}
        </div>
        <div className="nav-actions">
          <button type="button" className="theme-toggle" onClick={onLogout} aria-label="Log out">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
              <path d="M15 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8" />
              <path d="M10 12h11m0 0-3.5-3.5M21 12l-3.5 3.5" />
            </svg>
          </button>
          <button type="button" className="theme-toggle" onClick={onToggleTheme} aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>
        </div>
      </div>
    </nav>
  );
}
