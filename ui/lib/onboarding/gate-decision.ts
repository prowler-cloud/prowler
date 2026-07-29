import type { TourCompletionRecord } from "@/lib/tours/tour-types";

export interface GateDecisionInput {
  // `undefined` allowed; strict `=== false` check below fails open on ambiguous signals.
  hasProviders: boolean | undefined;
  completionRecord: TourCompletionRecord | null;
}

// Only forces onboarding when providers are provably absent and no record exists.
export function shouldStartOnboarding({
  hasProviders,
  completionRecord,
}: GateDecisionInput): boolean {
  const hasNoRecord =
    completionRecord === null || completionRecord === undefined;
  return hasProviders === false && hasNoRecord;
}
