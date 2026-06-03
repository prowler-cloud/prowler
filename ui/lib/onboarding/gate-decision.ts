import type { TourCompletionRecord } from "@/lib/tours/tour-types";

export interface GateDecisionInput {
  // Accepts `undefined` so callers can forward an ambiguous/failed provider
  // signal without casting. The strict `=== false` check below fails open on
  // anything that is not provably `false`.
  hasProviders: boolean | undefined;
  completionRecord: TourCompletionRecord | null;
}

// Mandatory new-user gate. The strict `=== false` check fails open: any
// ambiguous provider signal (`undefined`, `null`, error state) is treated as
// "do not force".
export function shouldStartOnboarding({
  hasProviders,
  completionRecord,
}: GateDecisionInput): boolean {
  const hasNoRecord =
    completionRecord === null || completionRecord === undefined;
  return hasProviders === false && hasNoRecord;
}
