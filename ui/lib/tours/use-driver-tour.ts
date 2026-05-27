"use client";

import "driver.js/dist/driver.css";

import { type Config, type Driver, driver, type DriveStep } from "driver.js";
import { useTheme } from "next-themes";
import { useEffect, useRef } from "react";

import { localStorageAdapter } from "./store/local-storage-adapter";
import type { TourCompletionStore } from "./store/tour-completion-store";
import { getDriverConfig, type TourTheme } from "./tour-config";
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

export interface UseDriverTourOptions {
  /** Auto-open the tour on mount when no completion record exists. Defaults to true. */
  autoOpen?: boolean;
  /**
   * Gate that delays initialization until the host says it's ready. Use this
   * when anchored steps target DOM that depends on async data (e.g. wait
   * until `!isLoading && items.length > 0`). Defaults to `true`.
   */
  enabled?: boolean;
  /** Custom completion store. Defaults to `localStorageAdapter`. */
  store?: TourCompletionStore;
  /** Optional driver.js config overrides for this tour. */
  configOverrides?: Partial<Config>;
  /**
   * Per-step async hooks indexed by step `target`. When provided for a
   * step, overrides driver.js's default Next/Back behaviour and delegates
   * progression to the handler. The handler receives a context with a
   * `waitForStep` helper for waiting on async DOM.
   */
  stepHandlers?: Record<string, TourStepHandlers>;
}

export interface UseDriverTourResult {
  /** Open the tour programmatically (e.g. from a "Show me how" button). */
  start: () => void;
  /** Close the tour programmatically. */
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

function adaptStep(tourId: string, step: TourStep): DriveStep {
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

function buildHandlerContext(tourId: string): TourStepHandlerContext {
  return {
    waitForStep: (target, options) =>
      waitForElement(toSelector(`${tourId}-${target}`), options),
  };
}

/**
 * React hook that drives a single `TourDefinition`. Initializes driver.js in
 * a client-only `useEffect`, derives `overlayColor` from `useTheme()`, and
 * rebuilds the driver instance when the active theme changes. Completion,
 * skip, and dismiss are persisted via the configured store.
 *
 * Returns imperative `start`/`stop` controls plus the boolean
 * `hasCompleted` so consumers can decide whether to render a replay CTA.
 */
export function useDriverTour(
  tour: TourDefinition,
  options: UseDriverTourOptions = {},
): UseDriverTourResult {
  const {
    autoOpen = true,
    enabled = true,
    store = localStorageAdapter,
    configOverrides,
    stepHandlers,
  } = options;

  const { resolvedTheme } = useTheme();
  const theme = resolveTheme(resolvedTheme);

  const driverRef = useRef<Driver | null>(null);
  const finalStateRef = useRef<TourCompletionRecord["state"]>(
    TOUR_COMPLETION_STATES.DISMISSED,
  );
  // Hold handlers in a ref so closures inside driver.js read the latest
  // version each step — without recreating the driver every render.
  const stepHandlersRef = useRef<Record<string, TourStepHandlers> | undefined>(
    stepHandlers,
  );
  stepHandlersRef.current = stepHandlers;

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

      // Wire onNextClick / onPrevClick lazily via the ref so handler
      // identity changes between renders never recreate the driver.
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
        persist(finalStateRef.current);
      },
    });

    const instance = driver(config);
    driverRef.current = instance;

    if (autoOpen && !hasCompleted) {
      const timer = window.setTimeout(() => {
        instance.drive();
      }, AUTO_OPEN_DELAY_MS);
      return () => {
        window.clearTimeout(timer);
        if (instance.isActive()) {
          instance.destroy();
        }
        driverRef.current = null;
      };
    }

    return () => {
      if (instance.isActive()) {
        instance.destroy();
      }
      driverRef.current = null;
    };
  }, [
    theme,
    tour,
    tourId,
    tourVersion,
    autoOpen,
    enabled,
    hasCompleted,
    store,
    configOverrides,
  ]);

  return {
    start: () => driverRef.current?.drive(),
    stop: () => driverRef.current?.destroy(),
    hasCompleted,
  };
}
