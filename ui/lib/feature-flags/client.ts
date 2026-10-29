"use client";

import { posthog } from "posthog-js";
import { useFeatureFlagEnabled } from "posthog-js/react";
import { useState } from "react";

import { useMountEffect } from "@/hooks/use-mount-effect";

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
// the flags request lands, `true` or `false` afterwards; a flag missing from
// the project resolves to OFF. The cloud fork inits PostHog in a mount effect
// at the app root, so once this component has mounted an unloaded client
// means nobody will init it (OSS): the flag can never turn on, so it is OFF.
export function useFeatureFlagState(flag: FeatureFlag): FeatureFlagState {
  const value = useFeatureFlagEnabled(flag);
  const [mounted, setMounted] = useState(false);
  useMountEffect(() => setMounted(true));
  if (value === undefined) {
    return mounted && !posthog.__loaded
      ? FEATURE_FLAG_STATE.OFF
      : FEATURE_FLAG_STATE.PENDING;
  }
  return value ? FEATURE_FLAG_STATE.ON : FEATURE_FLAG_STATE.OFF;
}

// Boolean flag. Only a resolved `true` counts: pending, disabled PostHog and
// a disabled flag all read as false.
export function useFeatureFlag(flag: FeatureFlag): boolean {
  return useFeatureFlagState(flag) === FEATURE_FLAG_STATE.ON;
}
