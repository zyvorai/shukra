// What the Isolate page may offer, decided from what the daemon says about
// enforcement. Kept apart from the page so the rules can be tested without a DOM.

export type Security = {
  enforcement?: string;
  allowList?: string[];
  reason?: string;
  /** True when enforcement outlives the daemon. */
  durable?: boolean;
};

export type Isolation = {
  vm: string;
  enforcement: string;
  applied: boolean;
  taps?: string[];
  reason: string;
  audit?: { result?: string; action?: string };
};

export type EnforcementView = {
  /** True only when the daemon can really enforce, so the controls may be used. */
  canAct: boolean;
  headline: string;
  detail: string;
  allow: string[];
  /** What happens to an isolated VM when the daemon stops. */
  whenDaemonStops: string;
};

export function describeEnforcement(sec: Security | null): EnforcementView {
  if (!sec) {
    return { canAct: false, headline: 'Checking enforcement…', detail: 'Waiting for the daemon.', allow: [], whenDaemonStops: '' };
  }
  const allow = sec.allowList ?? [];
  if (sec.enforcement === 'tcx') {
    return {
      canAct: true,
      headline: 'Isolate is enforced on the VM tap',
      detail: `An isolated VM keeps ARP, IPv6 neighbour discovery and traffic to or from ${allow.join(', ')}. Everything else on its tap is dropped.`,
      allow,
      whenDaemonStops: sec.durable
        ? 'It stays isolated if the daemon stops or crashes. Release it here, or with shukrad -detach-all if the daemon is down.'
        : 'It is re-applied when the daemon restarts, but the VM is reachable while the daemon is down.',
    };
  }
  return {
    canAct: false,
    headline: 'Isolate is not enforced',
    detail: sec.reason || 'The daemon has no enforcement attached. A request is only recorded.',
    allow,
    whenDaemonStops: '',
  };
}

/** How to word the result of an isolate or release, using only what the daemon reported. */
export function describeResult(r: Isolation, action: 'isolate' | 'release'): { ok: boolean; text: string } {
  const verb = action === 'isolate' ? 'isolated' : 'released';
  const taps = r.taps && r.taps.length > 0 ? ` (${r.taps.join(', ')})` : '';
  if (r.applied) return { ok: true, text: `${r.vm} ${verb}${taps}. ${r.reason}` };
  const how = r.audit?.result === 'partial' ? 'Only partly done' : r.audit?.result === 'refused' ? 'Refused' : 'Not applied';
  return { ok: false, text: `${how}. ${r.reason}` };
}
