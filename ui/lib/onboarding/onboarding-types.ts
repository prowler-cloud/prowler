import type { TourDefinition } from "@/lib/tours/tour-types";

// Single argument passed to every `isComplete(ctx)` predicate.
export interface OnboardingContext {
  hasProviders: boolean;
}

// Completion is persisted via the tour's own id/version — no second source of truth.
// `order` gaps are allowed; reordering is a data edit.
export interface OnboardingFlow {
  id: string;
  order: number;
  title: string;
  description: string;
  route: string;
  tour: TourDefinition;
  isComplete?: (ctx: OnboardingContext) => boolean;
  // When true, the page owns auto-open; OnboardingTrigger must not mount a second runner.
  ownsAutoOpen?: boolean;
  // Shown in the sequence banner when the step needs a completed scan to display data.
  dataRequirementHint?: string;
}
