import type { TourCompletionRecord } from "@/lib/tours/tour-types";

export interface GateDecisionInput {
  // Accepts `undefined` so callers can forward an ambiguous/failed provider
  // signal without casting. The strict `=== false` check below fails open on
  // anything that is not provably `false`.
  hasProviders: boolean | undefined;
  completionRecord: TourCompletionRecord | null;
}

// Pure decision for the mandatory new-user gate. Returns `true` only when the
// user provably has no providers AND no prior tour record exists in this
// browser. The strict `=== false` check fails open: any ambiguous provider
// signal (`undefined`, `null`, error state) is treated as "do not force".
// The explicit null/undefined check covers both an absent record and an
// unexpected `undefined` passed from a defensive caller.
export function shouldStartOnboarding({
  hasProviders,
  completionRecord,
}: GateDecisionInput): boolean {
  const hasNoRecord =
    completionRecord === null || completionRecord === undefined;
  return hasProviders === false && hasNoRecord;
}
