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
        "Attack Paths visualizes how a compromise in one resource could propagate through your cloud. We'll walk you through the workflow on your real data — no fake screenshots.",
    },
    {
      target: "intro",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Start with a scan",
      description:
        "Attack Paths analyses are generated from your existing scans. Each scan is a point-in-time snapshot of one cloud account.",
    },
    {
      target: "scan-list",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Pick a scan",
      description:
        "Each row is one of your scans. Normally you'd click the radio button on the left to pick one with graph data ready. To keep the tour moving, we'll auto-select the first ready scan when you click Next.",
    },
    {
      target: "query-selector",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Choose a query",
      description:
        "Predefined queries cover common risk patterns (privilege escalation, public exposure, lateral movement). You can also write your own openCypher. We'll pick the first one for you when you click Next.",
    },
    {
      target: "execute-button",
      side: TOUR_STEP_SIDES.TOP,
      align: TOUR_STEP_ALIGNMENTS.END,
      title: "Run it whenever you're ready",
      description:
        "Clicking this renders the result as an interactive graph. We'll stop the tour here so you can run it on your own data — or change the query first.",
    },
    {
      title: "You're set",
      description:
        "That's the whole loop: pick a scan, pick a query, execute. Clear browser storage if you want to see this tour again.",
    },
  ],
};
