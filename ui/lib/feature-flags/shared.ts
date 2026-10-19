// Registry of every feature flag key the UI reads. Side-effect free and
// SDK-agnostic so both client and server readers can import it. Every key
// lives here, including the ones only the cloud fork reads, so the registry
// never diverges between repos.
export const FEATURE_FLAG = {
  // Multivariate flag deciding which skill launcher the finding detail drawer
  // renders ("card" | "dropdown").
  SKILL_LAUNCHER: "finding-detail-skill-launcher",
  // Boolean flag gating the experimental Issues feature (contextual findings).
  // Read by cloud only.
  ISSUES: "issues-feature",
  // Boolean flag evaluated server-side per tenant in cloud. When on, it pins
  // the tenant to legacy billing; off or absent means the new Metronome system.
  BILLING_SYSTEM_METRONOME: "BILLING_SYSTEM_METRONOME",
} as const;

export type FeatureFlag = (typeof FEATURE_FLAG)[keyof typeof FEATURE_FLAG];
