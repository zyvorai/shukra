import { fixtureMode, fixtureResponse } from './fixtures';

const TOKEN = 'shukra-token';

export function token(): string {
  try {
    return sessionStorage.getItem(TOKEN) || '';
  } catch {
    return '';
  }
}

export function setToken(value: string) {
  try {
    if (value) sessionStorage.setItem(TOKEN, value);
    else sessionStorage.removeItem(TOKEN);
  } catch {
    /* ignore */
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  if (fixtureMode) return fixtureResponse(path, init) as T;
  const headers = new Headers(init?.headers);
  headers.set('Accept', 'application/json');
  const bearer = token();
  if (bearer) headers.set('Authorization', 'Bearer ' + bearer);
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    setToken('');
    window.dispatchEvent(new Event('shukra-auth-expired'));
    throw new Error('unauthorized');
  }
  if (!res.ok) throw new Error(await res.text());
  return res.json() as Promise<T>;
}

export async function probe(bearer: string): Promise<'ok' | 'unauthorized' | 'unreachable'> {
  if (fixtureMode) return bearer === 'shukra' ? 'ok' : 'unauthorized';
  try {
    const res = await fetch('/api/v1/status', {
      headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json' },
    });
    if (res.status === 401) return 'unauthorized';
    const ct = res.headers.get('content-type') || '';
    if (!res.ok || !ct.includes('application/json')) return 'unreachable';
    return 'ok';
  } catch {
    return 'unreachable';
  }
}
