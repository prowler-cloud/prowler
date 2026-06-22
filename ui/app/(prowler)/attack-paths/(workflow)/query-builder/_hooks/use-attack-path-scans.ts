"use client";

import { useRef, useState } from "react";

import { getAttackPathScans } from "@/actions/attack-paths";
import { useMountEffect } from "@/hooks/use-mount-effect";
import type { AttackPathScan } from "@/types/attack-paths";

export interface UseAttackPathScansOptions {
  /**
   * Invoked once the initial load resolves with no scan whose graph data is
   * ready (including empty results or a fetch failure). The page passes a
   * redirect only during onboarding replay; an established user gets `undefined`
   * and stays on the page.
   */
  onNoReadyScan?: () => void;
}

export interface UseAttackPathScansResult {
  scans: AttackPathScan[];
  scansLoading: boolean;
  loadError: boolean;
  refreshScans: () => Promise<void>;
  retryLoadScans: () => Promise<void>;
}

/**
 * `useData`-style hook owning the Attack Paths scan list. The direct
 * `useEffect` (via `useMountEffect`) lives here, not in the component: the
 * project forbids `useEffect` in components, but a reusable data hook is the
 * sanctioned place for a mount-time fetch when no fetching library is wired up.
 */
export function useAttackPathScans(
  options: UseAttackPathScansOptions = {},
): UseAttackPathScansResult {
  const { onNoReadyScan } = options;

  const [scans, setScans] = useState<AttackPathScan[]>([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const mountedRef = useRef(true);

  // Silent background refresh for auto-refresh: never flips loading/error, so it
  // can't disrupt the visible view if it fails.
  const refreshScans = async () => {
    try {
      const scansData = await getAttackPathScans();
      if (scansData?.data) {
        setScans(scansData.data);
      }
    } catch (error) {
      console.error("Failed to refresh scans:", error);
    }
  };

  // Full (re)load: drives loading + error state. Runs on mount and is reused by
  // the error view's Retry action. A successful empty result (`{ data: [] }`) is
  // not an error; only a missing payload or a thrown request is.
  const loadScans = async () => {
    setScansLoading(true);
    setLoadError(false);
    try {
      const scansData = await getAttackPathScans();
      if (!mountedRef.current) return;
      if (scansData?.data) {
        setScans(scansData.data);
        if (!scansData.data.some((scan) => scan.attributes.graph_data_ready)) {
          onNoReadyScan?.();
        }
      } else {
        setScans([]);
        setLoadError(true);
        onNoReadyScan?.();
      }
    } catch (error) {
      if (!mountedRef.current) return;
      console.error("Failed to load scans:", error);
      setScans([]);
      setLoadError(true);
      onNoReadyScan?.();
    } finally {
      if (mountedRef.current) setScansLoading(false);
    }
  };

  useMountEffect(() => {
    mountedRef.current = true;
    void loadScans();

    return () => {
      mountedRef.current = false;
    };
  });

  return {
    scans,
    scansLoading,
    loadError,
    refreshScans,
    retryLoadScans: loadScans,
  };
}
