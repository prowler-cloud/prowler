import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// Companion to `attack-paths.tour.ts` with a distinct id so completing one
// does not suppress the other.
export const attackPathsEmptyTour = defineTour({
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
});
