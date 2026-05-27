/**
 * Public types for the tour abstraction layer.
 *
 * Consumers MUST import types and runtime helpers from this module (or from
 * sibling modules under `ui/lib/tours/`), never from `driver.js` directly.
 * That keeps the library a swappable implementation detail.
 */

export const TOUR_COMPLETION_STATES = {
  COMPLETED: "completed",
  SKIPPED: "skipped",
  DISMISSED: "dismissed",
} as const;

export type TourCompletionState =
  (typeof TOUR_COMPLETION_STATES)[keyof typeof TOUR_COMPLETION_STATES];

export const TOUR_STEP_SIDES = {
  TOP: "top",
  RIGHT: "right",
  BOTTOM: "bottom",
  LEFT: "left",
  OVER: "over",
} as const;

export type TourStepSide =
  (typeof TOUR_STEP_SIDES)[keyof typeof TOUR_STEP_SIDES];

export const TOUR_STEP_ALIGNMENTS = {
  START: "start",
  CENTER: "center",
  END: "end",
} as const;

export type TourStepAlignment =
  (typeof TOUR_STEP_ALIGNMENTS)[keyof typeof TOUR_STEP_ALIGNMENTS];

/**
 * Identity of a tour at a specific version. A material content change to a
 * tour MUST bump `version` so users who completed a prior version see the
 * new one. Cosmetic edits keep the same version.
 */
export interface TourId {
  id: string;
  version: number;
}

/**
 * What gets persisted when a user finishes, skips, or dismisses a tour.
 * Storage adapters round-trip records of this shape.
 */
export interface TourCompletionRecord {
  tourId: string;
  version: number;
  state: TourCompletionState;
  completedAt: string;
}

/**
 * One step in a tour. A modal step (no anchor) omits `target`; an anchored
 * step provides the `data-tour-id` value (without the bracketed selector
 * wrapper). The tour hook composes the CSS selector `[data-tour-id="..."]`
 * and resolves the element lazily.
 */
export interface TourStep {
  target?: string;
  title?: string;
  description?: string;
  side?: TourStepSide;
  align?: TourStepAlignment;
  disableActiveInteraction?: boolean;
}

/**
 * A tour definition is authored once per `*.tour.ts` file and imported by
 * the page that opts the user in. `coversFiles` is consumed by the
 * `prowler-tour` maintenance skill to decide whether a change is
 * potentially tour-relevant.
 */
export interface TourDefinition {
  id: string;
  version: number;
  coversFiles: string[];
  steps: TourStep[];
}

/**
 * Context passed to per-step `onNext`/`onPrev` handlers. The host owns the
 * side effect (set state, push URL, fetch data) and then resolves the
 * promise — the hook advances driver.js once the promise settles.
 *
 * `waitForStep` resolves when an element with
 * `data-tour-id="<tour-id>-<target>"` exists in the document, useful when
 * the side effect causes a new panel to render asynchronously.
 */
export interface TourStepHandlerContext {
  waitForStep: (
    target: string,
    options?: WaitForStepOptions,
  ) => Promise<Element>;
}

export interface WaitForStepOptions {
  timeoutMs?: number;
}

/**
 * Per-step async hooks the host can register at the `useDriverTour` call
 * site, indexed by step `target`. When provided, the hook overrides
 * driver.js's default next/prev button behaviour for that step and
 * delegates progression to the handler.
 */
export interface TourStepHandlers {
  onNext?: (context: TourStepHandlerContext) => void | Promise<void>;
  onPrev?: (context: TourStepHandlerContext) => void | Promise<void>;
}
