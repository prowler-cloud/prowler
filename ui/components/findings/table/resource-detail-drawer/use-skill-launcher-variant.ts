"use client";

import { FEATURE_FLAG, useFeatureFlagVariant } from "@/lib/feature-flags";
import {
  SKILL_LAUNCHER_VARIANT,
  type SkillLauncherVariant,
} from "@/types/lighthouse-skills";

// Unresolved or unknown variants (including OSS builds that never init
// PostHog) fall back to the card control.
export function useSkillLauncherVariant(): SkillLauncherVariant {
  return useFeatureFlagVariant(
    FEATURE_FLAG.SKILL_LAUNCHER,
    Object.values(SKILL_LAUNCHER_VARIANT),
    SKILL_LAUNCHER_VARIANT.CARD,
  );
}
