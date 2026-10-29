"use client";

import { useEffect, useRef, useState } from "react";

import type { RealtimeResult } from "@/types/realtime";

interface UseRealtimeResourceOptions {
  /** Silent re-fetch period. Paused while the tab is hidden. */
  intervalMs?: number;
  enabled?: boolean;
}

const UNREACHABLE =
  "Prowler could not reach the Prowler Realtime service. Try again.";

/**
 * Loads one Prowler Realtime server action result and keeps it fresh.
 *
 * `key` identifies what is loaded (provider, filters, page): a new key hides
 * the old result and shows the loading state, while interval refreshes swap
 * the data in place so a live table does not flicker.
 */
export function useRealtimeResource<T>(
  fetcher: () => Promise<RealtimeResult<T>>,
  key: string,
  { intervalMs, enabled = true }: UseRealtimeResourceOptions = {},
) {
  // The result remembers the key it was loaded for, so a new key never
  // renders the previous key's data while its first request is in flight.
  const [state, setState] = useState<
    { key: string; result: RealtimeResult<T> } | undefined
  >();
  const [reloadCount, setReloadCount] = useState(0);
  const fetcherRef = useRef(fetcher);
  const requestRef = useRef(0);
  const loadKey = `${key}#${reloadCount}`;

  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    if (!enabled) return;

    const load = async () => {
      const request = ++requestRef.current;
      let next: RealtimeResult<T>;
      try {
        next = await fetcherRef.current();
      } catch {
        next = { ok: false, status: 0, error: UNREACHABLE };
      }
      // A newer request or a key change overtook this one: drop its answer.
      if (request === requestRef.current)
        setState({ key: loadKey, result: next });
    };

    void load();
    const timer = intervalMs
      ? setInterval(() => {
          if (document.visibilityState === "visible") void load();
        }, intervalMs)
      : undefined;

    return () => {
      requestRef.current++;
      if (timer) clearInterval(timer);
    };
  }, [loadKey, enabled, intervalMs]);

  const result = state?.key === loadKey ? state.result : undefined;

  return {
    result,
    loading: enabled && !result,
    data: result?.ok ? result.data : undefined,
    failure: result && !result.ok ? result : undefined,
    reload: () => setReloadCount((count) => count + 1),
    /** Replace the data without a round trip, e.g. with a save's answer. */
    setData: (data: T) =>
      setState({ key: loadKey, result: { ok: true, data } }),
  };
}
