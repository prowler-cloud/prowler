"use client";

import { useSyncExternalStore } from "react";

import { localStorageAdapter } from "./store/local-storage-adapter";
import type { TourCompletionRecord, TourId } from "./tour-types";

// Subscribes to cross-tab storage events only; same-tab writes manage their own state.
function subscribe(callback: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

// `localStorageAdapter.get` re-parses JSON each call; cache by serialized form to keep snapshot reference-stable.
const recordCache = new Map<string, TourCompletionRecord | null>();
const serializedCache = new Map<string, string | null>();

// Server snapshot is `null` (no localStorage), avoiding hydration mismatch.
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
