"use client";

import { useEffect, useEffectEvent, useRef, useState } from "react";

import { refreshRegistryCollections } from "@/actions/registry/registry";
import type { RegistryCollectionsResult } from "@/types/registry";

interface RegistryRefreshOptions {
  enabled: boolean;
  mutationPending: boolean;
  onResult: (result: RegistryCollectionsResult) => void;
}

export function useRegistryRefresh({
  enabled,
  mutationPending,
  onResult,
}: RegistryRefreshOptions) {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [requestId, setRequestId] = useState(0);
  const generation = useRef(0);
  const inFlight = useRef<number | null>(null);
  const requested = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);

  function requestRefresh() {
    // Tab/focus/button events share the current read unless a mutation invalidated it.
    if (inFlight.current === generation.current) return;
    requested.current = true;
    setRequestId((value) => value + 1);
  }

  function invalidateRefresh(refreshAfter?: boolean) {
    generation.current += 1;
    requested.current =
      refreshAfter ?? (requested.current || inFlight.current !== null);
    setRequestId((value) => value + 1);
  }

  const readCollections = useEffectEvent(async () => {
    if (!enabled) {
      generation.current += 1;
      requested.current = false;
      return;
    }
    if (mutationPending) {
      generation.current += 1;
      requested.current = requested.current || inFlight.current !== null;
      return;
    }
    if (!requested.current || inFlight.current !== null) return;
    const currentGeneration = generation.current;
    inFlight.current = currentGeneration;
    requested.current = false;
    setIsRefreshing(true);
    try {
      const result = await refreshRegistryCollections().catch(() => ({
        status: "error" as const,
      }));
      if (mounted.current && currentGeneration === generation.current)
        onResult(result);
    } finally {
      inFlight.current = null;
      if (mounted.current) {
        setIsRefreshing(false);
        if (requested.current) setRequestId((value) => value + 1);
      }
    }
  });

  useEffect(() => {
    void readCollections();
  }, [enabled, mutationPending, requestId]);

  const refreshOnFocus = useEffectEvent(() => {
    if (enabled && document.visibilityState === "visible") requestRefresh();
  });
  useEffect(() => {
    const refresh = () => refreshOnFocus();
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  return { isRefreshing, requestRefresh, invalidateRefresh };
}
