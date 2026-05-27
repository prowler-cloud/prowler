// @ts-nocheck -- template only; resolves once copied into `ui/lib/tours/`
/**
 * Tour template — copy this file to `ui/lib/tours/<your-id>.tour.ts` and
 * fill in the placeholders. See `references/tours-architecture.md` for the
 * design context.
 *
 * Conventions:
 *   - `id` is kebab-case and unique across all tours.
 *   - Anchored steps reference DOM via `data-tour-id="<id>-<step.target>"`;
 *     the hook composes the CSS selector automatically.
 *   - `coversFiles` lists the globs that describe the tour's surface; the
 *     `prowler-tour` skill consumes this to decide whether to evaluate
 *     drift on a given change.
 *   - Material flow changes bump `version`; cosmetic edits do not.
 */
import {
  TOUR_STEP_ALIGNMENTS,
  TOUR_STEP_SIDES,
  type TourDefinition,
} from "@/lib/tours/tour-types";

export const yourTour: TourDefinition = {
  id: "your-tour-id",
  version: 1,
  coversFiles: [
    // List the UI files this tour describes, using globs under `ui/`.
    // Example: "ui/app/(prowler)/your-feature/**"
  ],
  steps: [
    {
      // Modal step — no anchor. Use for intros, outros, and any step
      // that does not point at a specific DOM element.
      title: "Welcome",
      description: "Short, plain-English description.",
    },
    {
      // Anchored step. The hook resolves
      // `[data-tour-id="your-tour-id-step-name"]` lazily, so the element
      // can be conditionally rendered as long as it exists when the step
      // becomes active.
      target: "step-name",
      side: TOUR_STEP_SIDES.BOTTOM,
      align: TOUR_STEP_ALIGNMENTS.START,
      title: "Where the action is",
      description: "Tell the user what to look at here and why.",
    },
  ],
};
