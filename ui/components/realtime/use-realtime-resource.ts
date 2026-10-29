"use client";

import { useEffect, useRef, useState } from "react";

import type { RealtimeResult } from "@/types/realtime";

interface UseRealtimeResourceOptions {
  /** Silent re-fetch period. Paused while the tab is hidden. */
  intervalMs?: number;
  enabled?: boolean;
}

/**
 * Loads one Prowler Realtime server action result and keeps it fresh.
 *
 * `key` identifies what is loaded (provider, filters, page): a new key clears
 * the old result and shows the loading state, while interval refreshes swap
 * the data in place so a live table does not flicker.
 */
export function useRealtimeResource<T>(
  fetcher: () => Promise<RealtimeResult<T>>,
  key: string,
  { intervalMs, enabled = true }: UseRealtimeResourceOptions = {},
) {
  const [result, setResult] = useState<RealtimeResult<T> | undefined>();
  const [loading, setLoading] = useState(enabled);
  const [reloadCount, setReloadCount] = useState(0);
  const fetcherRef = useRef(fetcher);

  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;

    const load = async (silent: boolean) => {
      if (!silent) {
        setLoading(true);
        setResult(undefined);
      }
      const next = await fetcherRef.current();
      if (cancelled) return;
      setResult(next);
      setLoading(false);
    };

    void load(false);
    const timer = intervalMs
      ? setInterval(() => {
          if (document.visibilityState === "visible") void load(true);
        }, intervalMs)
      : undefined;

    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [key, enabled, intervalMs, reloadCount]);

  return {
    result,
    loading,
    data: result?.ok ? result.data : undefined,
    failure: result && !result.ok ? result : undefined,
    reload: () => setReloadCount((count) => count + 1),
    /** Replace the data without a round trip, e.g. with a save's answer. */
    setData: (data: T) => setResult({ ok: true, data }),
  };
}
