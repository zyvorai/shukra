import { useEffect, useState } from 'react';
import { api } from './api';

/** How often a live page refreshes. Fast enough to feel current, slow enough to be cheap. */
export const LIVE_MS = 5000;

/**
 * Fetches path, and again every refreshMs when it is set. A refresh keeps the
 * previous data on screen until the new data arrives, so nothing flashes or goes
 * blank, and a failed refresh keeps showing the last good data beside the error.
 * Polling pauses while the tab is hidden.
 */
export function useAPI<T>(path: string, opts: { refreshMs?: number } = {}) {
  const refreshMs = opts.refreshMs ?? 0;
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let stop = false;
    let timer: number | undefined;
    const schedule = () => {
      if (!stop && refreshMs > 0) timer = window.setTimeout(tick, refreshMs);
    };
    const load = () =>
      api<T>(path)
        .then((d) => {
          if (stop) return;
          setData(d);
          setErr('');
        })
        .catch((e: unknown) => {
          if (!stop) setErr(String(e));
        })
        .finally(schedule);
    const tick = () => {
      if (document.hidden) schedule();
      else void load();
    };
    void load();
    return () => {
      stop = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [path, refreshMs]);
  return { data, err };
}
