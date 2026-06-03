import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
} from "./tour-types";

// The literal targets this tour anchors, as a const map. `defineTour<...>`
// preserves the union so `useDriverTour` can validate `stepHandlers` keys and
// `waitForStep` arguments against exactly these values.
export const VIEW_FIRST_SCAN_TOUR_TARGETS = {
  LAUNCH: "launch",
  TABS: "tabs",
} as const;

export type ViewFirstScanTourTarget =
  (typeof VIEW_FIRST_SCAN_TOUR_TARGETS)[keyof typeof VIEW_FIRST_SCAN_TOUR_TARGETS];

export const viewFirstScanTour = defineTour<ViewFirstScanTourTarget>({
  id: "view-first-scan",
  version: 1,
  // Scopes the `tour:check` / `prowler-tour` drift check to the scans route and
  // component trees where the `launch` and `tabs` anchors live.
  coversFiles: ["ui/app/(prowler)/scans/**", "ui/components/scans/**"],
  steps: [
    {
      // Modal welcome step — no `target`, rendered as a centered popover.
      title: "This is Scan Jobs",
      description:
        "Scan Jobs is where you run and track scans against your connected providers.",
    },
    {
      target: "launch",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.END,
      title: "Launch a scan",
      description:
        "Click Launch Scan to start assessing a connected provider. You can pick which provider and what to scan.",
    },
    {
      target: "tabs",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Track your scan jobs",
      description:
        "Switch between these tabs to follow running, scheduled, and completed jobs as they progress.",
    },
  ],
});
