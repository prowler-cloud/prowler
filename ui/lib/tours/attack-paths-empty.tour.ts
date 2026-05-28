import {
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourDefinition,
} from "./tour-types";

/**
 * Attack Paths empty-state mini-tour.
 *
 * Fires when the user lands on Attack Paths with zero scans (after the
 * scans request has resolved — not while loading). Two steps: a short
 * modal pitch of what Attack Paths does, then an anchored highlight on
 * the "No scans available" alert pointing at the CTA. Persists separately
 * from the full `attack-paths` tour so completing one does not suppress
 * the other.
 *
 * Pairs with `attack-paths.tour.ts`: this one sets expectations before
 * the user has data; the full tour walks them through the workflow once
 * a scan is ready.
 */
export const attackPathsEmptyTour: TourDefinition = {
  id: "attack-paths-empty",
  version: 1,
  coversFiles: [
    "ui/app/(prowler)/attack-paths/**",
    "ui/components/attack-paths/**",
  ],
  steps: [
    {
      title: "Welcome to Attack Paths",
      description:
        "Attack Paths visualizes how a compromise in one resource could spread through your cloud — on your real data. To explore yours, you'll need a completed scan first.",
    },
    {
      target: "scans-cta",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Run your first scan",
      description:
        "Open Scan Jobs to launch one. The Attack Paths tour will pick up here once a scan is ready.",
    },
  ],
};
