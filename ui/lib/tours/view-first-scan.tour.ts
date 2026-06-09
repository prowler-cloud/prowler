import {
  defineTour,
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourDefinition,
} from "./tour-types";

// Const map keeps the union narrow so `useDriverTour` can validate step keys.
export const VIEW_FIRST_SCAN_TOUR_TARGETS = {
  // The first row of the active (In Progress) tab — present only while a scan runs.
  IN_PROGRESS: "in-progress",
  LAUNCH: "launch",
  TABS: "tabs",
} as const;

export type ViewFirstScanTourTarget =
  (typeof VIEW_FIRST_SCAN_TOUR_TARGETS)[keyof typeof VIEW_FIRST_SCAN_TOUR_TARGETS];

const COVERS_FILES = [
  "ui/app/(prowler)/scans/**",
  "ui/components/scans/**",
] as const;

// v2: lands on the In Progress tab and highlights the running scan when there is one.
const VERSION = 2;

const INTRO_STEP = {
  title: "This is Scan Jobs",
  description:
    "Scan Jobs is where you run and track scans against your connected providers.",
} as const;

/**
 * Builds the tour for the scans page. When a scan is already running we anchor the
 * In Progress row first (and mention the other tabs in copy); otherwise we fall back
 * to highlighting Launch Scan and the tabs. Gating on `hasInProgressScan` keeps the
 * tour from anchoring to a missing row — the same guard pattern the findings tour
 * uses for an empty table.
 */
export function buildViewFirstScanTour(
  hasInProgressScan: boolean,
): TourDefinition<ViewFirstScanTourTarget> {
  if (hasInProgressScan) {
    return defineTour<ViewFirstScanTourTarget>({
      id: "view-first-scan",
      version: VERSION,
      coversFiles: COVERS_FILES,
      steps: [
        INTRO_STEP,
        {
          target: "in-progress",
          side: TOUR_STEP_SIDES.BOTTOM,
          align: TOUR_STEP_ALIGNMENTS.START,
          title: "Your scan is running",
          description:
            "Prowler is assessing your provider right now. Use the In Progress, Completed, and Scheduled tabs to follow this and other jobs as they progress.",
        },
        {
          target: "launch",
          side: TOUR_STEP_SIDES.BOTTOM,
          align: TOUR_STEP_ALIGNMENTS.END,
          title: "Launch another scan",
          description:
            "Click Launch Scan whenever you want to assess another connected provider. You can pick which provider and what to scan.",
        },
      ],
    });
  }

  return defineTour<ViewFirstScanTourTarget>({
    id: "view-first-scan",
    version: VERSION,
    coversFiles: COVERS_FILES,
    steps: [
      INTRO_STEP,
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
}

// Default definition used by the onboarding registry; the scans page rebuilds it with
// the live `hasInProgressScan` flag at render time.
export const viewFirstScanTour = buildViewFirstScanTour(false);
