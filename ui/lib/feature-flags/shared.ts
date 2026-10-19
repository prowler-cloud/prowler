// Registry of every feature flag key the UI reads. Side-effect free and
// SDK-agnostic so both client and server readers can import it. The cloud
// fork extends this map with its own keys (billing, issues-feature, ...).
export const FEATURE_FLAG = {
  // Multivariate flag deciding which skill launcher the finding detail drawer
  // renders ("card" | "dropdown").
  SKILL_LAUNCHER: "finding-detail-skill-launcher",
} as const;

export type FeatureFlag = (typeof FEATURE_FLAG)[keyof typeof FEATURE_FLAG];
