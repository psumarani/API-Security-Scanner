import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";
import { errorMessage } from "../services/api";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/** Loads data on mount / when deps change. Optionally re-polls while `pollWhile(data)` is true. */
export function useAsync<T>(
  fn: () => Promise<T>,
  deps: DependencyList,
  options: { pollWhile?: (data: T) => boolean; intervalMs?: number } = {},
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const pollRef = useRef(options.pollWhile);
  pollRef.current = options.pollWhile;
  const interval = options.intervalMs ?? 2000;

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async (initial: boolean) => {
      if (initial) setLoading(true);
      try {
        const result = await fnRef.current();
        if (!active) return;
        setData(result);
        setError(null);
        if (pollRef.current?.(result)) timer = setTimeout(() => void run(false), interval);
      } catch (e) {
        if (!active) return;
        setError(errorMessage(e));
        if (!initial && pollRef.current) timer = setTimeout(() => void run(false), interval * 2);
      } finally {
        if (active && initial) setLoading(false);
      }
    };
    void run(true);
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, interval]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, reload };
}
