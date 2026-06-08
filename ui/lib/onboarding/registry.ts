import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { attackPathsTour } from "@/lib/tours/attack-paths.tour";
import { exploreFindingsTour } from "@/lib/tours/explore-findings.tour";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import type { TourCompletionStore } from "@/lib/tours/store/tour-completion-store";
import { viewComplianceTour } from "@/lib/tours/view-compliance.tour";
import { viewFirstScanTour } from "@/lib/tours/view-first-scan.tour";

import type { OnboardingContext, OnboardingFlow } from "./onboarding-types";

// Shown in the sequence banner when the step needs a completed scan.
const SCAN_DATA_HINT =
  "This step needs a completed scan to show data. Launch a scan first, or continue anyway.";

// Add a flow: one entry here + a `*.tour.ts` file. No gate/modal/nav edits needed.
export const onboardingFlows: readonly OnboardingFlow[] = [
  {
    id: "add-provider",
    order: 1,
    title: "Add your first provider",
    description:
      "Connect a cloud account so Prowler has something to scan and assess.",
    route: "/providers",
    tour: addProviderTour,
    // Server-derived: existing providers bypass this flow regardless of local record.
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
    ownsAutoOpen: true, // page drives this tour; OnboardingTrigger must not mount a second runner
  },
];

// Stable sort by `order`; `flows` defaults to the production registry so tests can inject.
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

// Complete when the server predicate returns true or a tour completion record exists.
function isFlowComplete(
  flow: OnboardingFlow,
  ctx: OnboardingContext,
  store: TourCompletionStore,
): boolean {
  if (flow.isComplete?.(ctx) === true) return true;
  return store.get(flow.tour) !== null;
}

// Returns the first incomplete flow by order, or `undefined` if all are done.
// Store is injected (default: localStorageAdapter) for testability.
export function getFirstIncompleteFlow(
  ctx: OnboardingContext,
  store: TourCompletionStore = localStorageAdapter,
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow | undefined {
  return getOrderedFlows(flows).find(
    (flow) => !isFlowComplete(flow, ctx, store),
  );
}
