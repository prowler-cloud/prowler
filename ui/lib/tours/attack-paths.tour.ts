import {
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourDefinition,
} from "./tour-types";

/**
 * Attack Paths in-product tour.
 *
 * Six steps walk a first-time user through the workflow: a modal welcome,
 * one anchored step on the page intro, then three anchored steps on the
 * scan-list table, the query selector, and the execute button. The tour
 * auto-drives the underlying UI between those anchors (host provides the
 * `onNext` handlers) so the user always sees the real interface, not just
 * descriptions of it. Final step is a modal outro.
 *
 * Bump `version` only when the user-visible flow changes materially.
 * Cosmetic edits (typos, copy clarification, selector renames that don't
 * change the journey) keep the same version. The `prowler-tour` skill
 * enforces this distinction.
 */
export const attackPathsTour: TourDefinition = {
  id: "attack-paths",
  version: 1,
  coversFiles: [
    "ui/app/(prowler)/attack-paths/**",
    "ui/components/attack-paths/**",
  ],
  steps: [
    {
      title: "Welcome to Attack Paths",
      description:
        "Attack Paths visualizes how a compromise in one resource could spread through your cloud — on your real data.",
    },
    {
      target: "intro",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Start with a scan",
      description:
        "Attack Paths analyses are generated from your existing scans. Each scan is a point-in-time snapshot of one provider.",
    },
    {
      target: "scan-list",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Pick a scan",
      description:
        "Each row is a scan. Click the radio button on the left to select one.",
    },
    {
      target: "query-selector",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Choose a query",
      description:
        "Predefined queries cover common risk patterns (privilege escalation, public exposure, lateral movement). You can also write your own openCypher.",
    },
    {
      target: "execute-button",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.END,
      title: "Run it whenever you're ready",
      description:
        "Click Execute Query to see the graph with the possible attack paths.",
    },
    {
      title: "You're all set",
      description:
        "Explore the attack paths and dig into anything that looks risky.",
    },
  ],
};
