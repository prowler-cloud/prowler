import type { TourCompletionRecord } from "@/lib/tours/tour-types";

export interface GateDecisionInput {
  // `undefined` allowed; strict `=== false` check below fails open on ambiguous signals.
  hasProviders: boolean | undefined;
  // Limited-visibility users list zero providers in a tenant that is not empty.
  canManageProviders: boolean;
  completionRecord: TourCompletionRecord | null;
}

// Only forces onboarding when providers are provably absent, the user can add one
// and no record exists.
export function shouldStartOnboarding({
  hasProviders,
  canManageProviders,
  completionRecord,
}: GateDecisionInput): boolean {
  const hasNoRecord =
    completionRecord === null || completionRecord === undefined;
  return hasProviders === false && canManageProviders && hasNoRecord;
}
