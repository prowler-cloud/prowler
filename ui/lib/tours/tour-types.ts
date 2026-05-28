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

// Modal step omits `target`; anchored step provides the `data-tour-id` value
// (no brackets). The hook composes the `[data-tour-id="..."]` selector and
// resolves the element lazily.
export interface TourStep {
  target?: string;
  title?: string;
  description?: string;
  side?: TourStepSide;
  align?: TourStepAlignment;
  disableActiveInteraction?: boolean;
}

// `coversFiles` is consumed by the `prowler-tour` skill to scope drift checks.
export interface TourDefinition {
  id: string;
  version: number;
  coversFiles: string[];
  steps: TourStep[];
}

// The hook advances driver.js once the handler's promise settles.
// `waitForStep` resolves when an element with `data-tour-id="<tour-id>-<target>"`
// exists in the document.
export interface TourStepHandlerContext {
  waitForStep: (
    target: string,
    options?: WaitForStepOptions,
  ) => Promise<Element>;
}

export interface WaitForStepOptions {
  timeoutMs?: number;
}

// Indexed by step `target`. When provided, overrides driver.js's default
// Next/Back for that step and delegates progression to the handler.
export interface TourStepHandlers {
  onNext?: (context: TourStepHandlerContext) => void | Promise<void>;
  onPrev?: (context: TourStepHandlerContext) => void | Promise<void>;
}
