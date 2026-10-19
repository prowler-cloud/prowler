"use client";

import {
  useFeatureFlagEnabled,
  useFeatureFlagVariantKey,
} from "posthog-js/react";

import {
  FEATURE_FLAG_STATE,
  type FeatureFlag,
  type FeatureFlagState,
} from "./shared";

// The only place in ui/ that imports posthog-js/react's flag hooks, so
// swapping the flag provider later is a one-file change. The hooks read the
// global posthog singleton from posthog-js/react's default context and need
// no provider here: whoever initializes PostHog (the cloud fork) feeds them.
// OSS builds that never init PostHog resolve every read to its fallback.

// Boolean flag with its resolution state. PostHog reports `undefined` until
// the flags request lands (or forever when it was never initialized), `true`
// or `false` afterwards; a flag missing from the project resolves to OFF.
export function useFeatureFlagState(flag: FeatureFlag): FeatureFlagState {
  const value = useFeatureFlagEnabled(flag);
  if (value === undefined) return FEATURE_FLAG_STATE.PENDING;
  return value ? FEATURE_FLAG_STATE.ON : FEATURE_FLAG_STATE.OFF;
}

// Boolean flag. Only a resolved `true` counts: pending, disabled PostHog and
// a disabled flag all read as false.
export function useFeatureFlag(flag: FeatureFlag): boolean {
  return useFeatureFlagState(flag) === FEATURE_FLAG_STATE.ON;
}

// Multivariate flag. Returns the resolved key when it is one of `variants`;
// unresolved, boolean or unknown values fall back to `fallback`.
export function useFeatureFlagVariant<T extends string>(
  flag: FeatureFlag,
  variants: readonly T[],
  fallback: T,
): T {
  const value = useFeatureFlagVariantKey(flag);
  const match = variants.find((variant) => variant === value);
  return match ?? fallback;
}
