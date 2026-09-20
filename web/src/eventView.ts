/** Filtering, ordering and paging of the event tables, kept apart from the components so it can be tested. */

export type Ev = Record<string, unknown>;

/** The filter value for events that belong to no VM: connects made by host processes such as k3s or cilium. */
export const NO_VM = '_host';

/** How many rows a table shows before "show more". */
export const PAGE = 50;

/** The VM an event was joined to, or '' for a host process. */
export function vmOf(e: Ev): string {
  const vm = e.vm as { name?: string } | undefined;
  return vm?.name ?? '';
}

/** Whether an event belongs to the chosen VM ('' is every event, NO_VM is those with no VM). */
export function inVM(e: Ev, vm: string): boolean {
  if (vm === '') return true;
  if (vm === NO_VM) return vmOf(e) === '';
  return vmOf(e) === vm;
}

/** Whether any of the fields an operator would search on contains q, ignoring case. An empty q matches everything. */
export function hasText(e: Ev, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (needle === '') return true;
  return ['dst', 'src', 'dport', 'dns_name', 'kind', 'qtype', 'proto', 'attribution'].some((k) => {
    const v = e[k];
    return v !== undefined && v !== null && String(v).toLowerCase().includes(needle);
  });
}

/** Newest first. Timestamps are ISO 8601 in UTC, so they order as text. */
export function newestFirst<T extends Ev>(events: T[]): T[] {
  return [...events].sort((a, b) => String(b.ts ?? '').localeCompare(String(a.ts ?? '')));
}

export function page<T>(rows: T[], limit: number): { shown: T[]; total: number; more: number } {
  const shown = rows.slice(0, Math.max(0, limit));
  return { shown, total: rows.length, more: rows.length - shown.length };
}
