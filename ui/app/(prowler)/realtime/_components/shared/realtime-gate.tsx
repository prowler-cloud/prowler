"use client";

import type { ReactNode } from "react";

import { useFeatureFlagState } from "@/lib/feature-flags/client";
import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "@/lib/feature-flags/shared";

interface RealtimeGateProps {
  children: ReactNode;
  /** Shown while PostHog answers, sized like the page so nothing jumps. */
  pending: ReactNode;
}

/**
 * Per-account rollout. The Cloud gate (404) runs on the server first, and the
 * API checks the same flag, so this only decides what the browser shows.
 */
export function RealtimeGate({ children, pending }: RealtimeGateProps) {
  const state = useFeatureFlagState(FEATURE_FLAG.REALTIME);
  if (state === FEATURE_FLAG_STATE.ON) return <>{children}</>;
  if (state === FEATURE_FLAG_STATE.PENDING) return <>{pending}</>;
  return (
    <p className="text-text-neutral-tertiary text-sm">
      Prowler Realtime is not available for this account yet.
    </p>
  );
}
