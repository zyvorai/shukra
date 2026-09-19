import { useEffect, useState } from 'react';
import { api } from './api';

export function useAPI<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let stop = false;
    api<T>(path)
      .then((d) => {
        if (!stop) setData(d);
      })
      .catch((e: unknown) => {
        if (!stop) setErr(String(e));
      });
    return () => {
      stop = true;
    };
  }, [path]);
  return { data, err };
}
