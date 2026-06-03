import type { TourDefinition } from "@/lib/tours/tour-types";

// Server-derived signals the gate and flow-completion checks consult.
// Kept intentionally minimal: only `hasProviders` is needed today, and the
// shape is the single argument passed to every `isComplete(ctx)` predicate.
export interface OnboardingContext {
  hasProviders: boolean;
}

// A single onboarding flow. The flow *is* its tour: completion persistence
// reuses the tour's own `TourCompletionRecord` (via the tour's id/version),
// so there is no second source of truth. `order` is an explicit integer
// (gaps allowed) so reordering is a data edit, never a code move.
export interface OnboardingFlow {
  id: string;
  order: number;
  title: string;
  description: string;
  route: string;
  tour: TourDefinition;
  isComplete?: (ctx: OnboardingContext) => boolean;
  // When true, the route's PAGE already drives this flow's tour (e.g.
  // attack-paths). The shared OnboardingTrigger must NOT mount a runner for it;
  // the page owns auto-open and reports completion to the sequence slice.
  // Additive, optional, defaults to undefined/false.
  ownsAutoOpen?: boolean;
  // Optional hint shown in the sequence banner when this step needs scan data
  // to display anything meaningful (e.g. findings, compliance, attack-paths).
  // The banner surfaces it as a muted/warning note so the user knows they can
  // launch a scan first or continue anyway. Additive, optional.
  dataRequirementHint?: string;
}
