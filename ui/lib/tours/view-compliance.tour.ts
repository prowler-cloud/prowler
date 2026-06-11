import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourStepHandlers,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const VIEW_COMPLIANCE_TOUR_TARGETS = {
  FRAMEWORKS: "frameworks",
  SEARCH: "search",
} as const;

export type ViewComplianceTourTarget =
  (typeof VIEW_COMPLIANCE_TOUR_TARGETS)[keyof typeof VIEW_COMPLIANCE_TOUR_TARGETS];

export const viewComplianceTour = defineTour<ViewComplianceTourTarget>({
  id: "view-compliance",
  version: 1,
  coversFiles: [
    "ui/app/(prowler)/compliance/**",
    "ui/components/compliance/**",
  ],
  steps: [
    {
      title: "Check your compliance",
      description:
        "Compliance maps your findings to frameworks like CIS so you can see where you stand against each standard.",
    },
    {
      target: "search",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Find a framework fast",
      description:
        "Search by name to jump straight to a specific framework instead of scrolling through every card.",
    },
    {
      target: "frameworks",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Browse the frameworks",
      description:
        "Each card is a framework with your passed and total requirement counts. Continue and we'll open the first one so you can drill into its requirements.",
    },
  ],
});

// Step handlers are passed to `useDriverTour` at consumption time (not part of `TourDefinition`).
// `search` resets the query so the frameworks anchor is back in the DOM (an empty result
// set unmounts every card, including the anchored one, and breaks navigation otherwise).
// `frameworks` is the last step: opening the card navigates to the detail route, and the
// tour is destroyed as completed (persisted synchronously) before the grid unmounts.
export function createViewComplianceTourStepHandlers(handlers: {
  /** Clears the search box; returns false when no framework card will render. */
  resetSearch: () => boolean;
  /** Opens the first framework card's detail page. */
  openFirstFramework: () => void;
}): {
  [K in ViewComplianceTourTarget]?: TourStepHandlers<ViewComplianceTourTarget>;
} {
  return {
    [VIEW_COMPLIANCE_TOUR_TARGETS.SEARCH]: {
      onNext: async ({ waitForStep }) => {
        // No card at all → skip the wait so the tour doesn't hang; driver advances next.
        if (!handlers.resetSearch()) return;
        await waitForStep(VIEW_COMPLIANCE_TOUR_TARGETS.FRAMEWORKS);
      },
    },
    [VIEW_COMPLIANCE_TOUR_TARGETS.FRAMEWORKS]: {
      onNext: () => {
        handlers.openFirstFramework();
      },
    },
  };
}
