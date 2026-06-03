import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { exploreFindingsTour } from "@/lib/tours/explore-findings.tour";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import type { TourCompletionStore } from "@/lib/tours/store/tour-completion-store";
import { viewComplianceTour } from "@/lib/tours/view-compliance.tour";
import { viewFirstScanTour } from "@/lib/tours/view-first-scan.tour";

import type { OnboardingContext, OnboardingFlow } from "./onboarding-types";

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
  },
  {
    id: "view-compliance",
    order: 4,
    title: "Check compliance",
    description: "Map your findings to frameworks like CIS.",
    route: "/compliance",
    tour: viewComplianceTour,
  },
];

// Returns flows sorted ascending by `order`. The sort is stable: entries that
// share an `order` value keep their original relative position. The `flows`
// argument defaults to the production registry; tests inject fixtures.
export function getOrderedFlows(
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow[] {
  return flows
    .map((flow, index) => ({ flow, index }))
    .sort((a, b) => a.flow.order - b.flow.order || a.index - b.index)
    .map(({ flow }) => flow);
}

// Resolves a flow by its stable `id`, or `undefined` when none matches.
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

// Returns the first flow (by `order`) that is NOT complete, or `undefined`
// when every flow is complete. The store is injected with a production default
// (`localStorageAdapter`) so the function stays pure and unit-testable: tests
// pass an in-memory store instead of mocking localStorage.
export function getFirstIncompleteFlow(
  ctx: OnboardingContext,
  store: TourCompletionStore = localStorageAdapter,
  flows: readonly OnboardingFlow[] = onboardingFlows,
): OnboardingFlow | undefined {
  return getOrderedFlows(flows).find(
    (flow) => !isFlowComplete(flow, ctx, store),
  );
}
