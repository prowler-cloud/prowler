"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";

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
      if (onRefresh) {
        // Use custom refresh callback for client-side state management
        onRefresh();
      } else {
        // Default: trigger server-side refresh
        router.refresh();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [hasExecutingScan, router, searchParams, onRefresh]);

  return null;
}
