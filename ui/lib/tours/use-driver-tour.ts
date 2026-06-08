"use client";

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

function adaptStep<TTarget extends string>(
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
        persist(finalStateRef.current);
        onClosedRef.current?.(finalStateRef.current);
      },
    });

    driverRef.current = driver(config);

    return () => {
      const instance = driverRef.current;
      if (instance?.isActive()) {
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
        instance.drive();
      }
    }, AUTO_OPEN_DELAY_MS);

    return () => {
      window.clearTimeout(timer);
    };
  }, [autoOpen, enabled, hasCompleted, tourId, tourVersion]);

  return {
    start: () => driverRef.current?.drive(),
    stop: () => driverRef.current?.destroy(),
    hasCompleted,
  };
}
