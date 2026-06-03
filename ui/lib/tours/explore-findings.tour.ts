import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// The literal targets this tour anchors. `defineTour<...>` preserves the union
// so `useDriverTour` can validate `stepHandlers` keys and `waitForStep`
// arguments against exactly these two values.
export type ExploreFindingsTourTarget = "filters" | "table";

export const exploreFindingsTour = defineTour<ExploreFindingsTourTarget>({
  id: "explore-findings",
  version: 1,
  // Scopes the `tour:check` / `prowler-tour` drift check to the findings route
  // and component trees where the `filters` and `table` anchors live.
  coversFiles: ["ui/app/(prowler)/findings/**", "ui/components/findings/**"],
  steps: [
    {
      // Modal welcome step — no `target`, rendered as a centered popover.
      title: "Explore your findings",
      description:
        "Findings are the issues Prowler detected across your scans, grouped so you can act on what matters most.",
    },
    {
      // `filters` is anchored before `table`: the filter controls render
      // immediately, while the table mounts after its Suspense boundary
      // resolves, so this ordering keeps both anchors resolvable in turn.
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
