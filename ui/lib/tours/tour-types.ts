// Import from this module — never from `driver.js` directly — to keep the
// library a swappable implementation detail.

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

export interface TourId {
  id: string;
  version: number;
}

export interface TourCompletionRecord {
  tourId: string;
  version: number;
  state: TourCompletionState;
  completedAt: string;
}

// Modal step omits `target`; anchored step provides the `data-tour-id` value (no brackets).
export interface TourStep<TTarget extends string = string> {
  target?: TTarget;
  title?: string;
  description?: string;
  side?: TourStepSide;
  align?: TourStepAlignment;
  disableActiveInteraction?: boolean;
  // Step with no Next/Back buttons (only Close); the flow advances via imperative
  // `advanceActiveTour()` calls from the covered UI instead of popover clicks. Used
  // when progress is driven by a user action (e.g. picking a provider type) rather
  // than the tour's own button.
  autoAdvance?: boolean;
}

// `coversFiles` is consumed by the `prowler-tour` skill to scope drift checks.
export interface TourDefinition<TTarget extends string = string> {
  id: string;
  version: number;
  coversFiles: readonly string[];
  steps: ReadonlyArray<TourStep<TTarget>>;
}

// `waitForStep` resolves when `data-tour-id="<tour-id>-<target>"` appears in the document.
export interface TourStepHandlerContext<TTarget extends string = string> {
  waitForStep: (
    target: TTarget,
    options?: WaitForStepOptions,
  ) => Promise<Element>;
}

export interface WaitForStepOptions {
  timeoutMs?: number;
}

// Overrides driver.js's default Next/Back for the step it's registered on.
export interface TourStepHandlers<TTarget extends string = string> {
  onNext?: (context: TourStepHandlerContext<TTarget>) => void | Promise<void>;
  onPrev?: (context: TourStepHandlerContext<TTarget>) => void | Promise<void>;
}

// Use instead of `: TourDefinition` to preserve literal step targets for `stepHandlers`/`waitForStep` validation.
export function defineTour<const TTarget extends string>(
  definition: TourDefinition<TTarget>,
): TourDefinition<TTarget> {
  return definition;
}
