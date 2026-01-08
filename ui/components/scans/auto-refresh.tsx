"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";

interface AutoRefreshProps {
  hasExecutingScan: boolean;
}

export function AutoRefresh({ hasExecutingScan }: AutoRefreshProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (!hasExecutingScan) return;

    // Don't auto-refresh if scan details drawer is open
    const scanId = searchParams.get("scanId");
    if (scanId) return;

    const interval = setInterval(() => {
      router.refresh();
    }, 5000);

    return () => clearInterval(interval);
  }, [hasExecutingScan, router, searchParams]);

  return null;
}
