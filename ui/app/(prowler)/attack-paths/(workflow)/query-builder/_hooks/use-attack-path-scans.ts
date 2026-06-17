"use client";

import { useState } from "react";

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
  refreshScans: () => Promise<void>;
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

  useMountEffect(() => {
    let active = true;

    const loadScans = async () => {
      setScansLoading(true);
      try {
        const scansData = await getAttackPathScans();
        const nextScans = scansData?.data ?? [];
        if (!active) return;
        setScans(nextScans);
        if (!nextScans.some((scan) => scan.attributes.graph_data_ready)) {
          onNoReadyScan?.();
        }
      } catch (error) {
        if (!active) return;
        console.error("Failed to load scans:", error);
        setScans([]);
        onNoReadyScan?.();
      } finally {
        if (active) setScansLoading(false);
      }
    };

    void loadScans();

    return () => {
      active = false;
    };
  });

  return { scans, scansLoading, refreshScans };
}
