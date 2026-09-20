import { useState } from 'react';
import { useAPI } from './useAPI';

type VMList = { vms?: { name: string }[] };

/**
 * State for a VM-name field. Until the operator types, the field holds the first VM the daemon
 * actually knows about, so a page never opens on a name that does not exist on this host. names
 * feeds the field's suggestions.
 */
export function useVMName() {
  const { data } = useAPI<VMList>('/api/v1/vms');
  const names = (data?.vms ?? []).map((v) => v.name);
  const [typed, setTyped] = useState<string | null>(null);
  return { vm: typed ?? names[0] ?? '', setVM: setTyped, names };
}
