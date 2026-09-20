/** The API paths the Explain page asks for, kept apart from the component so they can be tested. */

/** Look-back choices for a live verdict (the daemon keeps six minutes of history in memory). */
export const LIVE_WINDOWS = [
  { value: '60s', label: 'last minute' },
  { value: '5m', label: 'last 5 minutes' },
  { value: 'lifetime', label: 'since the daemon attached' },
];

/** Look-back choices for a verdict at a past time (built from stored snapshots, 5 minutes apart). */
export const PAST_WINDOWS = [
  { value: '15m', label: '15 minutes before' },
  { value: '1h', label: 'an hour before' },
  { value: '6h', label: '6 hours before' },
];

/** A datetime-local value ("2026-09-20T03:12", in the browser's zone) as the UTC time the API takes, or '' for "now". */
export function atFromInput(value: string): string {
  if (value === '') return '';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

export function explainPath(vm: string, window: string, at: string): string {
  const q = new URLSearchParams({ vm, window });
  if (at !== '') q.set('at', at);
  return `/api/v1/explain?${q.toString()}`;
}

export function incidentPath(vm: string, window: string, at: string): string {
  const q = new URLSearchParams({ vm, window });
  if (at !== '') q.set('at', at);
  return `/api/v1/incident?${q.toString()}`;
}

/** A file name for a downloaded bundle that is safe on any file system. */
export function incidentFileName(vm: string, at: string): string {
  const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, '_');
  return `shukra-incident-${safe(vm) || 'vm'}-${safe(at === '' ? 'now' : at)}.json`;
}
