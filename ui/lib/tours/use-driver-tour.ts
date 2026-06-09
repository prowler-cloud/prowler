"use client";

// driver.js's own stylesheet provides the overlay/stage geometry and base popover
// positioning. tours.css only themes on top of it (strips the popover chrome so our
// React card shows). Without this import the spotlight and popover placement break.
import "driver.js/dist/driver.css";

import { type Config, type Driver, driver, type DriveStep } from "driver.js";
import { useTheme } from "next-themes";
import { useEffect, useRef } from "react";

import { localStorageAdapter } from "./store/local-storage-adapter";
import type { TourCompletionStore } from "./store/tour-completion-store";
import { getDriverConfig, type TourTheme } from "./tour-config";
import { unmountActiveTourPopover } from "./tour-popover-render";
import {
  TOUR_COMPLETION_STATES,
  type TourCompletionRecord,
  type TourDefinition,
  type TourStep,
  type TourStepHandlerContext,
  type TourStepHandlers,
  type WaitForStepOptions,
} from "./tour-types";

const AUTO_OPEN_DELAY_MS = 50;
const DEFAULT_WAIT_TIMEOUT_MS = 8000;

// Handle to the tour that is currently driving. driver.js permits a single active
// tour at a time, so one module-level ref is enough. It lets imperative callers
// outside the tour's React subtree end it — e.g. the provider wizard ends the
// add-provider tour once the user advances past the anchored step, so driver.js's
// overlay stops applying `pointer-events: none` to the rest of the wizard's inputs.
let activeTourInstance: Driver | null = null;

/** Ends whatever tour is currently driving. No-op when none is active. */
export function endActiveTour(): void {
  const instance = activeTourInstance;
  activeTourInstance = null;
  if (!instance?.isActive()) return;
  // Defer out of React's render/commit cycle: destroy() synchronously unmounts the
  // popover's React root (see tour-popover-render), and React 19 throws if that
  // happens mid-render — e.g. when this is called from an effect reacting to a
  // provider-type selection. The microtask runs before paint, so no visible flash.
  queueMicrotask(() => {
    if (instance.isActive()) instance.destroy();
  });
}

/**
 * Advances the currently driving tour by one step. No-op when none is active or
 * the tour is already on its last step. Used to drive `autoAdvance` steps — those
 * have no Next button, so the covered UI moves the tour forward when the user takes
 * the expected action (e.g. the provider wizard advances past the provider-type
 * step once a type is picked).
 */
export function advanceActiveTour(): void {
  const instance = activeTourInstance;
  if (!instance?.isActive()) return;
  // Same React-19 reason as endActiveTour: moveNext re-renders the popover via
  // flushSync, which throws if called mid-render (this fires from a change handler).
  // Idempotent: re-checking isActive/isLastStep inside the microtask means repeat
  // calls after reaching the final step are no-ops, never overshooting.
  queueMicrotask(() => {
    if (instance.isActive() && !instance.isLastStep()) instance.moveNext();
  });
}

/**
 * Advances the active tour once `targetSelector` appears in the DOM. Used when the
 * next step anchors to an element that mounts asynchronously after a user action —
 * e.g. clicking "Add a Provider" opens the wizard, and the provider-type anchor only
 * exists once the modal renders. No-op when no tour is active; silently gives up if
 * the element never mounts (e.g. the modal was closed again).
 */
export function advanceActiveTourWhenReady(targetSelector: string): void {
  const instance = activeTourInstance;
  if (!instance?.isActive()) return;
  waitForElement(targetSelector)
    .then(() => {
      // .then is already off the render path, so moveNext()'s flushSync is safe here
      // (same pattern as the step onNext handlers below).
      if (instance.isActive() && !instance.isLastStep()) instance.moveNext();
    })
    .catch(() => {
      // Target never appeared (e.g. the wizard was dismissed); leave the tour as-is.
    });
}

export interface UseDriverTourOptions<TTarget extends string = string> {
  /** Auto-open on mount when no completion record exists. Defaults to true. */
  autoOpen?: boolean;
  /** Gate that delays initialization until anchored DOM is ready. Defaults to true. */
  enabled?: boolean;
  /** Defaults to `localStorageAdapter`. */
  store?: TourCompletionStore;
  configOverrides?: Partial<Config>;
  /** Indexed by step `target`; overrides driver.js's default Next/Back for that step. */
  stepHandlers?: { [K in TTarget]?: TourStepHandlers<TTarget> };
  /** Fired after persist when the tour is destroyed; invoked via ref so identity changes don't recreate the driver. */
  onClosed?: (state: TourCompletionRecord["state"]) => void;
}

export interface UseDriverTourResult {
  start: () => void;
  stop: () => void;
  /** True if a completion record exists for `(tour.id, tour.version)`. */
  hasCompleted: boolean;
}

function resolveTheme(resolvedTheme: string | undefined): TourTheme {
  return resolvedTheme === "dark" ? "dark" : "light";
}

function toSelector(target: string): string {
  return `[data-tour-id="${target}"]`;
}

/** Builds the `[data-tour-id="<tourId>-<target>"]` selector for a step's anchor. */
export function getTourTargetSelector(tourId: string, target: string): string {
  return toSelector(`${tourId}-${target}`);
}

function waitForElement(
  selector: string,
  options: WaitForStepOptions = {},
): Promise<Element> {
  const { timeoutMs = DEFAULT_WAIT_TIMEOUT_MS } = options;
  if (typeof document === "undefined") {
    return Promise.reject(new Error("waitForElement called without a DOM"));
  }

  const existing = document.querySelector(selector);
  if (existing) return Promise.resolve(existing);

  return new Promise((resolve, reject) => {
    const observer = new MutationObserver(() => {
      const found = document.querySelector(selector);
      if (found) {
        observer.disconnect();
        window.clearTimeout(timer);
        resolve(found);
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    const timer = window.setTimeout(() => {
      observer.disconnect();
      reject(
        new Error(
          `Tour element ${selector} did not appear within ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);
  });
}

// Exported for unit testing the step → driver.js mapping (e.g. autoAdvance buttons).
export function adaptStep<TTarget extends string>(
  tourId: string,
  step: TourStep<TTarget>,
): DriveStep {
  const driveStep: DriveStep = {
    popover: {
      title: step.title,
      description: step.description,
      side: step.side,
      align: step.align,
    },
  };

  if (step.target) {
    const selector = toSelector(`${tourId}-${step.target}`);
    driveStep.element = () => {
      if (typeof document === "undefined") {
        throw new Error("Tour element resolved without a DOM");
      }
      const found = document.querySelector(selector);
      if (!found) {
        throw new Error(
          `Tour "${tourId}" references missing selector: ${selector}`,
        );
      }
      return found;
    };
  }

  if (step.disableActiveInteraction !== undefined) {
    driveStep.disableActiveInteraction = step.disableActiveInteraction;
  }

  if (step.autoAdvance) {
    // No Next/Back — only Close. driver.js hides the other buttons (display:none),
    // so the React popover's showNext/showPrevious resolve false. The flow advances
    // via advanceActiveTour() called imperatively from the covered UI.
    driveStep.popover = { ...driveStep.popover, showButtons: ["close"] };
  }

  return driveStep;
}

function nowIso(): string {
  return new Date().toISOString();
}

function buildHandlerContext<TTarget extends string>(
  tourId: string,
): TourStepHandlerContext<TTarget> {
  return {
    waitForStep: (target, options) =>
      waitForElement(toSelector(`${tourId}-${target}`), options),
  };
}

// Generic over `TTarget` so `stepHandlers` keys and `waitForStep` calls are type-checked against the tour's literal union.
export function useDriverTour<TTarget extends string>(
  tour: TourDefinition<TTarget>,
  options: UseDriverTourOptions<TTarget> = {},
): UseDriverTourResult {
  const {
    autoOpen = true,
    enabled = true,
    store = localStorageAdapter,
    configOverrides,
    stepHandlers,
    onClosed,
  } = options;

  const { resolvedTheme } = useTheme();
  const theme = resolveTheme(resolvedTheme);

  const driverRef = useRef<Driver | null>(null);
  const finalStateRef = useRef<TourCompletionRecord["state"]>(
    TOUR_COMPLETION_STATES.DISMISSED,
  );
  // Widened internally: indexing `{ [K in TTarget]?: ... }` by a generic `TTarget` resolves to `never`.
  const stepHandlersRef = useRef<
    Record<string, TourStepHandlers<TTarget> | undefined> | undefined
  >(stepHandlers as Record<string, TourStepHandlers<TTarget> | undefined>);
  stepHandlersRef.current = stepHandlers as
    | Record<string, TourStepHandlers<TTarget> | undefined>
    | undefined;

  // Stable ref — not in the effect dep array, so changing identity never recreates the driver.
  const onClosedRef = useRef<
    ((state: TourCompletionRecord["state"]) => void) | undefined
  >(onClosed);
  onClosedRef.current = onClosed;

  // True while an involuntary teardown is in flight (theme re-render / unmount).
  // driver.js's destroy() bypasses onDestroyStarted but still fires onDestroyed, so
  // without this flag onDestroyed would persist the default DISMISSED record and the
  // tour would be marked resolved forever after a simple theme toggle.
  const teardownRef = useRef(false);

  const tourId = tour.id;
  const tourVersion = tour.version;
  const existing = store.get({ id: tourId, version: tourVersion });
  const hasCompleted = existing !== null;

  useEffect(() => {
    // Skip in vitest — the driver.js overlay would race click-through tests.
    if (process.env.NODE_ENV === "test") return;
    if (!enabled) return;
    if (tour.steps.length === 0) return;

    finalStateRef.current = TOUR_COMPLETION_STATES.DISMISSED;
    const tourKey = { id: tourId, version: tourVersion };

    const persist = (state: TourCompletionRecord["state"]) => {
      store.set(tourKey, {
        tourId,
        version: tourVersion,
        state,
        completedAt: nowIso(),
      });
    };

    const handlerContext = buildHandlerContext(tourId);

    const steps: DriveStep[] = tour.steps.map((step) => {
      const driveStep = adaptStep(tourId, step);
      const target = step.target;
      if (!target) return driveStep;

      // Read handlers via ref so identity changes don't recreate the driver.
      driveStep.popover = {
        ...driveStep.popover,
        onNextClick: (_element, _step, { driver: instance }) => {
          const handler = stepHandlersRef.current?.[target]?.onNext;
          if (!handler) {
            instance.moveNext();
            return;
          }
          Promise.resolve(handler(handlerContext))
            .then(() => {
              if (instance.isActive()) instance.moveNext();
            })
            .catch((err) => {
              console.error(
                `Tour "${tourId}" step "${target}" onNext failed:`,
                err,
              );
              if (instance.isActive()) instance.destroy();
            });
        },
        onPrevClick: (_element, _step, { driver: instance }) => {
          const handler = stepHandlersRef.current?.[target]?.onPrev;
          if (!handler) {
            instance.movePrevious();
            return;
          }
          Promise.resolve(handler(handlerContext))
            .then(() => {
              if (instance.isActive()) instance.movePrevious();
            })
            .catch((err) => {
              console.error(
                `Tour "${tourId}" step "${target}" onPrev failed:`,
                err,
              );
              if (instance.isActive()) instance.destroy();
            });
        },
      };

      return driveStep;
    });

    const config = getDriverConfig(theme, {
      ...configOverrides,
      steps,
      onDestroyStarted: (_element, _step, { driver: instance }) => {
        if (instance.isLastStep()) {
          finalStateRef.current = TOUR_COMPLETION_STATES.COMPLETED;
        } else {
          finalStateRef.current = TOUR_COMPLETION_STATES.SKIPPED;
        }
        instance.destroy();
      },
      onDestroyed: () => {
        unmountActiveTourPopover();
        if (activeTourInstance === driverRef.current) {
          activeTourInstance = null;
        }
        // Involuntary teardown: close the tour without recording a resolution so it
        // can reappear later (e.g. the user just switched theme mid-tour).
        if (teardownRef.current) {
          teardownRef.current = false;
          return;
        }
        persist(finalStateRef.current);
        onClosedRef.current?.(finalStateRef.current);
      },
    });

    driverRef.current = driver(config);

    return () => {
      const instance = driverRef.current;
      if (instance?.isActive()) {
        teardownRef.current = true;
        instance.destroy();
      }
      unmountActiveTourPopover();
      driverRef.current = null;
    };
  }, [theme, tour, tourId, tourVersion, enabled, store, configOverrides]);

  useEffect(() => {
    // Skip in vitest — the driver.js overlay would race click-through tests.
    if (process.env.NODE_ENV === "test") return;
    if (!enabled || !autoOpen || hasCompleted) return;

    const instance = driverRef.current;
    if (!instance || instance.isActive()) return;

    const timer = window.setTimeout(() => {
      if (!instance.isActive()) {
        activeTourInstance = instance;
        instance.drive();
      }
    }, AUTO_OPEN_DELAY_MS);

    return () => {
      window.clearTimeout(timer);
    };
  }, [autoOpen, enabled, hasCompleted, tourId, tourVersion]);

  return {
    start: () => {
      const instance = driverRef.current;
      if (!instance) return;
      activeTourInstance = instance;
      instance.drive();
    },
    stop: () => driverRef.current?.destroy(),
    hasCompleted,
  };
}
