"use client";

import type { ReactNode } from "react";

import {
  FEATURE_FLAG_STATE,
  type FeatureFlag,
  useFeatureFlagState,
} from "@/lib/feature-flags";

interface FeatureFlagGateProps {
  flag: FeatureFlag;
  children: ReactNode;
  // Rendered once the flag resolves to off. Defaults to nothing.
  fallback?: ReactNode;
  // Rendered while the flag is unresolved. Defaults to nothing so an enabled
  // user never sees the off-state fallback flash before PostHog answers, and
  // a build that never initializes PostHog shows neither branch.
  pending?: ReactNode;
}

// Client gate over a boolean feature flag. Server-rendered children are still
// produced on the server (RSC payload); the gate only decides what the
// browser shows, so keep it for presentation, not for authorization.
export function FeatureFlagGate({
  flag,
  children,
  fallback = null,
  pending = null,
}: FeatureFlagGateProps) {
  const state = useFeatureFlagState(flag);
  if (state === FEATURE_FLAG_STATE.ON) return <>{children}</>;
  if (state === FEATURE_FLAG_STATE.PENDING) return <>{pending}</>;
  return <>{fallback}</>;
}
