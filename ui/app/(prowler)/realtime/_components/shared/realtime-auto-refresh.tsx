"use client";

import { useRouter } from "next/navigation";

import { useMountEffect } from "@/hooks/use-mount-effect";

interface RealtimeAutoRefreshProps {
  intervalMs: number;
}

/**
 * Re-renders the page's server components every `intervalMs` while the tab is
 * visible. One request per tick, instead of one server action per panel.
 * Remount with a `key` to change the interval.
 */
export function RealtimeAutoRefresh({ intervalMs }: RealtimeAutoRefreshProps) {
  const router = useRouter();

  useMountEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") router.refresh();
    }, intervalMs);
    return () => window.clearInterval(timer);
  });

  return null;
}
