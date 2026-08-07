"use client";

import { useFeatureFlagVariantKey } from "posthog-js/react";

import {
  SKILL_LAUNCHER_FLAG,
  SKILL_LAUNCHER_VARIANT,
  type SkillLauncherVariant,
} from "@/types/lighthouse-skills";

// The hook reads the global posthog singleton (posthog-js/react's default
// context), so it needs no provider or init here: the cloud fork initializes
// and identifies the client; OSS builds never resolve the flag and fall back
// to the card control, as do unresolved or unknown variants.
export function useSkillLauncherVariant(): SkillLauncherVariant {
  const value = useFeatureFlagVariantKey(SKILL_LAUNCHER_FLAG);
  return value === SKILL_LAUNCHER_VARIANT.DROPDOWN
    ? SKILL_LAUNCHER_VARIANT.DROPDOWN
    : SKILL_LAUNCHER_VARIANT.CARD;
}
