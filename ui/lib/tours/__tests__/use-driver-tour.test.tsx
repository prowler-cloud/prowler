import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { addProviderTour } from "../add-provider.tour";
import type { TourCompletionRecord } from "../tour-types";
import {
  adaptStep,
  advanceActiveTour,
  endActiveTour,
  useDriverTour,
} from "../use-driver-tour";

// Hook short-circuits driver.js in NODE_ENV=test; asserts public contract only.
// Driver.js close behavior is covered by E2E (slice 9).

function HookProbe({
  onClosed,
  onResult,
}: {
  onClosed?: (state: TourCompletionRecord["state"]) => void;
  onResult: (result: ReturnType<typeof useDriverTour>) => void;
}) {
  const result = useDriverTour(addProviderTour, { autoOpen: false, onClosed });
  onResult(result);
  return null;
}

describe("useDriverTour onClosed option", () => {
  it("accepts the onClosed option and returns the existing result surface", () => {
    const onClosed = vi.fn();
    const results: ReturnType<typeof useDriverTour>[] = [];

    render(<HookProbe onClosed={onClosed} onResult={(r) => results.push(r)} />);

    const result = results.at(-1);
    expect(result).toBeDefined();
    expect(typeof result?.start).toBe("function");
    expect(typeof result?.stop).toBe("function");
    expect(typeof result?.hasCompleted).toBe("boolean");
    // onClosed is input-only; it must not leak into the returned surface
    expect(result && "onClosed" in result).toBe(false);
  });

  it("keeps the same result surface when onClosed is omitted (backward-compatible)", () => {
    const results: ReturnType<typeof useDriverTour>[] = [];

    render(<HookProbe onResult={(r) => results.push(r)} />);

    const result = results.at(-1);
    expect(result).toBeDefined();
    expect(typeof result?.start).toBe("function");
    expect(typeof result?.stop).toBe("function");
    expect(typeof result?.hasCompleted).toBe("boolean");
  });
});

describe("endActiveTour", () => {
  // The actual destroy path runs only outside NODE_ENV=test (driver.js is
  // short-circuited here), so this asserts the imperative escape hatch the
  // provider wizard relies on is exported and safe to call unconditionally.
  it("is a no-op that does not throw when no tour is active", () => {
    expect(() => endActiveTour()).not.toThrow();
    expect(endActiveTour()).toBeUndefined();
  });
});

describe("advanceActiveTour", () => {
  // Sibling escape hatch to endActiveTour: the wizard calls it on provider-type
  // selection to move past the autoAdvance step. Same NODE_ENV=test short-circuit.
  it("is a no-op that does not throw when no tour is active", () => {
    expect(() => advanceActiveTour()).not.toThrow();
    expect(advanceActiveTour()).toBeUndefined();
  });
});

describe("adaptStep autoAdvance", () => {
  it("limits an autoAdvance step's popover to the close button only", () => {
    const driveStep = adaptStep("add-provider", {
      target: "provider-type",
      autoAdvance: true,
      title: "Pick a provider type",
    });

    // No Next/Back — the covered UI drives the flow via advanceActiveTour().
    expect(driveStep.popover?.showButtons).toEqual(["close"]);
  });

  it("leaves showButtons unset on a normal step (driver.js defaults apply)", () => {
    const driveStep = adaptStep("add-provider", {
      target: "trigger",
      title: "Open the wizard",
    });

    expect(driveStep.popover?.showButtons).toBeUndefined();
  });
});

describe("adaptStep selector fallback", () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it("uses the fallback target when the primary target disappears", () => {
    // Given
    const fallbackElement = document.createElement("div");
    fallbackElement.dataset.tourId = "view-first-scan-tabs";
    document.body.append(fallbackElement);
    const driveStep = adaptStep("view-first-scan", {
      target: "in-progress",
      fallbackTarget: "tabs",
      title: "Your scan is running",
    });

    // When
    const resolvedElement = (driveStep.element as () => Element)();

    // Then
    expect(resolvedElement).toBe(fallbackElement);
  });

  it("keeps the primary target when both targets exist", () => {
    // Given
    const primaryElement = document.createElement("div");
    primaryElement.dataset.tourId = "view-first-scan-in-progress";
    const fallbackElement = document.createElement("div");
    fallbackElement.dataset.tourId = "view-first-scan-tabs";
    document.body.append(primaryElement, fallbackElement);
    const driveStep = adaptStep("view-first-scan", {
      target: "in-progress",
      fallbackTarget: "tabs",
      title: "Your scan is running",
    });

    // When
    const resolvedElement = (driveStep.element as () => Element)();

    // Then
    expect(resolvedElement).toBe(primaryElement);
  });

  it("still reports configuration drift when both targets are missing", () => {
    // Given
    const driveStep = adaptStep("view-first-scan", {
      target: "in-progress",
      fallbackTarget: "tabs",
      title: "Your scan is running",
    });

    // When
    const resolveElement = () => (driveStep.element as () => Element)();

    // Then
    expect(resolveElement).toThrow(
      'Tour "view-first-scan" references missing selector: [data-tour-id="view-first-scan-in-progress"]',
    );
  });
});
