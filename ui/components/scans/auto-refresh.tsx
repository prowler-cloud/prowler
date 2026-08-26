"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

/**
 * Signals that a poll cycle ran, not that fresh data landed: the default branch
 * calls the fire-and-forget `router.refresh()`, which reports neither.
 * Listeners must read authoritative state themselves.
 */
export const SCAN_POLL_TICK_EVENT = "prowler:scan-poll-tick";

/** Signals the transition from an executing scan to no executing scan. */
export const SCAN_EXECUTION_SETTLED_EVENT = "prowler:scan-execution-settled";

interface AutoRefreshProps {
  hasExecutingScan: boolean;
  /** Optional callback for client-side refresh (used when data is managed in local state) */
  onRefresh?: () => void | Promise<void>;
}

const useAutoRefresh = ({ hasExecutingScan, onRefresh }: AutoRefreshProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const refreshInProgress = useRef(false);
  const previouslyExecuting = useRef(hasExecutingScan);

  useEffect(() => {
    if (previouslyExecuting.current && !hasExecutingScan) {
      window.dispatchEvent(new Event(SCAN_EXECUTION_SETTLED_EVENT));
    }

    previouslyExecuting.current = hasExecutingScan;
  }, [hasExecutingScan]);

  useEffect(() => {
    if (!hasExecutingScan) return;

    // Don't auto-refresh if scan details drawer is open
    const scanId = searchParams.get("scanId");
    if (scanId) return;

    let active = true;
    const interval = setInterval(() => {
      if (refreshInProgress.current) return;

      const refresh = async () => {
        refreshInProgress.current = true;

        try {
          if (onRefresh) {
            // Use custom refresh callback for client-side state management
            await onRefresh();
          } else {
            // Default: trigger server-side refresh
            router.refresh();
          }
        } catch (error) {
          console.error("Scan auto-refresh failed:", error);
          return;
        } finally {
          refreshInProgress.current = false;
        }

        if (active) {
          window.dispatchEvent(new Event(SCAN_POLL_TICK_EVENT));
        }
      };

      void refresh();
    }, 5000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [hasExecutingScan, router, searchParams, onRefresh]);
};

export function AutoRefresh(props: AutoRefreshProps) {
  useAutoRefresh(props);

  return null;
}
