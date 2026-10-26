// Registry of every feature flag key the UI reads. Side-effect free and
// SDK-agnostic so both client and server readers can import it. Every key
// lives here, including the ones only the cloud fork reads, so the registry
// never diverges between repos.
export const FEATURE_FLAG = {
  // Boolean flag gating the experimental Issues feature (contextual findings).
  // Read by cloud only.
  ISSUES: "issues-feature",
  // Boolean flag evaluated server-side per tenant in cloud. When on, it pins
  // the tenant to legacy billing; off or absent means the new Metronome system.
  BILLING_SYSTEM_METRONOME: "BILLING_SYSTEM_METRONOME",
  // Boolean flag evaluated server-side per tenant in cloud. When on, trial
  // tenants only preview the most critical finding groups on /findings.
  FINDINGS_TRIAL_PREVIEW: "findings-trial-preview",
} as const;

export type FeatureFlag = (typeof FEATURE_FLAG)[keyof typeof FEATURE_FLAG];

// Resolution state of a boolean flag. PENDING covers both "flags still
// loading" and "PostHog never initialized" (OSS builds): neither case can
// tell whether the flag is on, so gates render neither branch yet.
export const FEATURE_FLAG_STATE = {
  PENDING: "pending",
  ON: "on",
  OFF: "off",
} as const;

export type FeatureFlagState =
  (typeof FEATURE_FLAG_STATE)[keyof typeof FEATURE_FLAG_STATE];
