import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { attackPathsTour } from "@/lib/tours/attack-paths.tour";
import { exploreFindingsTour } from "@/lib/tours/explore-findings.tour";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import type { TourCompletionStore } from "@/lib/tours/store/tour-completion-store";
import { viewComplianceTour } from "@/lib/tours/view-compliance.tour";
import { viewFirstScanTour } from "@/lib/tours/view-first-scan.tour";

import type { OnboardingContext, OnboardingFlow } from "./onboarding-types";

// Shared hint for steps whose pages render nothing until a scan has completed.
// Surfaced in the sequence banner so the user can launch a scan first or move
// on at their own pace.
const SCAN_DATA_HINT =
  "This step needs a completed scan to show data. Launch a scan first, or continue anyway.";

// Single source of truth for onboarding flows. Adding a flow is one entry here
// plus its `*.tour.ts` file — no gate, modal, or nav edits required. `order`
// is an explicit integer (gaps allowed) so reordering is a data edit.
export const onboardingFlows: readonly OnboardingFlow[] = [
  {
    id: "add-provider",
    order: 1,
    title: "Add your first provider",
    description:
      "Connect a cloud account so Prowler has something to scan and assess.",
    route: "/providers",
    tour: addProviderTour,
    // Server-derived authority: a user who already has providers is never
    // gated into this flow, even with no local completion record.
    isComplete: (ctx) => ctx.hasProviders,
  },
  {
    id: "view-first-scan",
    order: 2,
    title: "Run your first scan",
    description:
      "Launch a scan and watch Prowler assess your connected provider.",
    route: "/scans",
    tour: viewFirstScanTour,
  },
  {
    id: "explore-findings",
    order: 3,
    title: "Explore your findings",
    description: "See what Prowler detected and how to fix it.",
    route: "/findings",
    tour: exploreFindingsTour,
    dataRequirementHint: SCAN_DATA_HINT,
  },
  {
    id: "view-compliance",
    order: 4,
    title: "Check compliance",
    description: "Map your findings to frameworks like CIS.",
    route: "/compliance",
    tour: viewComplianceTour,
    dataRequirementHint: SCAN_DATA_HINT,
  },
  {
    id: "attack-paths",
    order: 5,
    title: "Visualize attack paths",
    description: "See how a compromise could spread across your cloud.",
    route: "/attack-paths",
    tour: attackPathsTour,
    dataRequirementHint: SCAN_DATA_HINT,
    // The attack-paths PAGE already drives this tour, so the shared
    // OnboardingTrigger must NOT mount a second runner.
    ownsAutoOpen: true,
  },
];

// Stable sort by `order`: entries sharing an `order` keep their original
// relative position. `flows` defaults to the production registry; tests inject.
export function getOrderedFlows(
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow[] {
  return flows
    .map((flow, index) => ({ flow, index }))
    .sort((a, b) => a.flow.order - b.flow.order || a.index - b.index)
    .map(({ flow }) => flow);
}

export function getFlowById(
  id: string,
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow | undefined {
  return flows.find((flow) => flow.id === id);
}

// A flow is complete when its server-derived predicate says so OR a tour
// completion record already exists in the store for its tour.
function isFlowComplete(
  flow: OnboardingFlow,
  ctx: OnboardingContext,
  store: TourCompletionStore,
): boolean {
  if (flow.isComplete?.(ctx) === true) return true;
  return store.get(flow.tour) !== null;
}

// First incomplete flow by `order`, or `undefined` when all are complete. The
// store is injected (default `localStorageAdapter`) so the function stays pure
// and unit-testable without mocking localStorage.
export function getFirstIncompleteFlow(
  ctx: OnboardingContext,
  store: TourCompletionStore = localStorageAdapter,
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow | undefined {
  return getOrderedFlows(flows).find(
    (flow) => !isFlowComplete(flow, ctx, store),
  );
}
