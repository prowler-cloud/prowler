import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const EXPLORE_FINDINGS_TOUR_TARGETS = {
  FILTERS: "filters",
  TABLE: "table",
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
      // `filters` renders immediately; `table` waits on Suspense — order matters.
      target: "filters",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Focus on what matters",
      description:
        "Filter by provider, severity, service, and more to narrow down to the findings you care about.",
    },
    {
      target: "table",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Open a finding group",
      description:
        "Each row groups related findings. Open one to see the affected resources and how to remediate them.",
    },
  ],
});
