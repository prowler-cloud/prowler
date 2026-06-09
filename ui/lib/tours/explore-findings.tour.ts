import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourStepHandlers,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const EXPLORE_FINDINGS_TOUR_TARGETS = {
  FILTERS: "filters",
  // Anchored to the first finding group row (there may be only one), not the whole table.
  GROUP: "group",
  // The expanded resources panel revealed after opening a finding group.
  RESOURCES: "resources",
} as const;

export type ExploreFindingsTourTarget =
  (typeof EXPLORE_FINDINGS_TOUR_TARGETS)[keyof typeof EXPLORE_FINDINGS_TOUR_TARGETS];

export const exploreFindingsTour = defineTour<ExploreFindingsTourTarget>({
  id: "explore-findings",
  version: 1,
  coversFiles: ["ui/app/(prowler)/findings/**", "ui/components/findings/**"],
  steps: [
    {
      title: "Explore your findings",
      description:
        "Findings are the issues Prowler detected across your scans, grouped so you can act on what matters most.",
    },
    {
      // `filters` renders immediately; `group` waits on Suspense — order matters.
      target: "filters",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Focus on what matters",
      description:
        "Filter by provider, severity, service, and more to narrow down to the findings you care about.",
    },
    {
      target: "group",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Open a finding group",
      description:
        "Each row groups related findings from a single check. Continue and we'll open the first one for you.",
    },
    {
      target: "resources",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Review the affected resources",
      description:
        "These are the resources flagged by the check. Click any row to inspect the finding details and how to remediate it.",
    },
  ],
});

// Step handlers are passed to `useDriverTour` at consumption time (not part of `TourDefinition`).
// `group` opens the first finding group and waits for the resources panel before advancing.
export function createExploreFindingsTourStepHandlers(
  openFirstGroup: () => boolean,
): {
  [K in ExploreFindingsTourTarget]?: TourStepHandlers<ExploreFindingsTourTarget>;
} {
  return {
    [EXPLORE_FINDINGS_TOUR_TARGETS.GROUP]: {
      onNext: async ({ waitForStep }) => {
        // No drillable group → skip the wait so the tour doesn't hang; driver advances next.
        if (!openFirstGroup()) return;
        await waitForStep(EXPLORE_FINDINGS_TOUR_TARGETS.RESOURCES);
      },
    },
  };
}
