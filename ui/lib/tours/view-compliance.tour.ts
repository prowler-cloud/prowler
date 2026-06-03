import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// The literal targets this tour anchors. `defineTour<...>` preserves the union
// so `useDriverTour` can validate `stepHandlers` keys and `waitForStep`
// arguments against exactly these two values.
export type ViewComplianceTourTarget = "frameworks" | "search";

export const viewComplianceTour = defineTour<ViewComplianceTourTarget>({
  id: "view-compliance",
  version: 1,
  // Scopes the `tour:check` / `prowler-tour` drift check to the compliance
  // route and component trees where the `frameworks` and `search` anchors live.
  coversFiles: [
    "ui/app/(prowler)/compliance/**",
    "ui/components/compliance/**",
  ],
  steps: [
    {
      // Modal welcome step — no `target`, rendered as a centered popover.
      title: "Check your compliance",
      description:
        "Compliance maps your findings to frameworks like CIS so you can see where you stand against each standard.",
    },
    {
      target: "frameworks",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Browse the frameworks",
      description:
        "Each card is a framework with your passed and total requirement counts. Open one to drill into its requirements.",
    },
    {
      target: "search",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Find a framework fast",
      description:
        "Search by name to jump straight to a specific framework instead of scrolling through every card.",
    },
  ],
});
