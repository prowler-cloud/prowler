"use client";

import type { ReactNode } from "react";

import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import { FEATURE_FLAG } from "@/lib/feature-flags";

interface RealtimeGateProps {
  children: ReactNode;
  /** Shown while PostHog answers, sized like the page so nothing jumps. */
  pending: ReactNode;
}

/** Per-account rollout. The Cloud gate (404) runs on the server first. */
export function RealtimeGate({ children, pending }: RealtimeGateProps) {
  return (
    <FeatureFlagGate
      flag={FEATURE_FLAG.REALTIME}
      pending={pending}
      fallback={
        <p className="text-text-neutral-tertiary text-sm">
          Prowler Realtime is not available for this account yet.
        </p>
      }
    >
      {children}
    </FeatureFlagGate>
  );
}
