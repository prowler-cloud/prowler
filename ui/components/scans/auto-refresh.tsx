"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";

/**
 * Signals that a poll cycle ran, not that fresh data landed: the default branch
 * calls the fire-and-forget `router.refresh()`, which reports neither.
 * Listeners must read authoritative state themselves.
 */
export const SCAN_POLL_TICK_EVENT = "prowler:scan-poll-tick";

interface AutoRefreshProps {
  hasExecutingScan: boolean;
  /** Optional callback for client-side refresh (used when data is managed in local state) */
  onRefresh?: () => void | Promise<void>;
}

export function AutoRefresh({ hasExecutingScan, onRefresh }: AutoRefreshProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (!hasExecutingScan) return;

    // Don't auto-refresh if scan details drawer is open
    const scanId = searchParams.get("scanId");
    if (scanId) return;

    const interval = setInterval(() => {
      const refresh = async () => {
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
        }

        window.dispatchEvent(new Event(SCAN_POLL_TICK_EVENT));
      };

      void refresh();
    }, 5000);

    return () => clearInterval(interval);
  }, [hasExecutingScan, router, searchParams, onRefresh]);

  return null;
}
