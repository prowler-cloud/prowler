"use client";

import { useSyncExternalStore } from "react";

import { localStorageAdapter } from "./store/local-storage-adapter";
import type { TourCompletionRecord, TourId } from "./tour-types";

// Cross-tab storage updates. Same-tab writes come from event handlers that also
// drive their own session state, so they do not rely on this subscription.
function subscribe(callback: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

// `useSyncExternalStore` bails out of re-rendering only when `getSnapshot`
// returns a reference-equal value. `localStorageAdapter.get` re-parses JSON into
// a fresh object every call, so we cache the parsed record per tour and reuse it
// while the serialized form is unchanged — keeping the snapshot stable.
const recordCache = new Map<string, TourCompletionRecord | null>();
const serializedCache = new Map<string, string | null>();

// SSR-safe read of a tour's completion record. The server snapshot is `null`
// (no localStorage), so the first client render matches the server and there is
// no hydration mismatch — replacing a client-only `useEffect` read.
export function useTourCompletion(
  tour: TourId | null,
): TourCompletionRecord | null {
  const getSnapshot = (): TourCompletionRecord | null => {
    if (!tour) return null;
    const cacheKey = `${tour.id}.v${tour.version}`;
    const record = localStorageAdapter.get(tour);
    const serialized = record ? JSON.stringify(record) : null;
    if (serializedCache.get(cacheKey) !== serialized) {
      serializedCache.set(cacheKey, serialized);
      recordCache.set(cacheKey, record);
    }
    return recordCache.get(cacheKey) ?? null;
  };

  return useSyncExternalStore(subscribe, getSnapshot, () => null);
}
