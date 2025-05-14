"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

interface AutoRefreshProps {
  hasExecutingScan: boolean;
}

export function AutoRefresh({ hasExecutingScan }: AutoRefreshProps) {
  const router = useRouter();

  useEffect(() => {
    if (!hasExecutingScan) return;

    const interval = setInterval(() => {
      router.refresh();
    }, 5000);

    return () => clearInterval(interval);
  }, [hasExecutingScan, router]);

  return null;
}
