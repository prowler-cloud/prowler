import { describe, expect, it, vi } from "vitest";

import {
  createViewComplianceTourStepHandlers,
  viewComplianceTour,
  type ViewComplianceTourTarget,
} from "../view-compliance.tour";

// Only these two carry a `data-tour-id` in the UI; welcome step has no target.
const ALLOWED_TARGETS = ["frameworks", "search"] as const;

const definedTargets = (): ViewComplianceTourTarget[] =>
  viewComplianceTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ViewComplianceTourTarget => target !== undefined,
    );

describe("viewComplianceTour shape", () => {
  it("declares the view-compliance id", () => {
    expect(viewComplianceTour.id).toBe("view-compliance");
  });

  it("declares a positive integer version", () => {
    expect(Number.isInteger(viewComplianceTour.version)).toBe(true);
    expect(viewComplianceTour.version).toBeGreaterThan(0);
  });

  it("anchors exactly the search and frameworks steps, in that order", () => {
    // Search sits above the cards in the DOM; the tour must follow top-to-bottom
    // so the spotlight never jumps back up the page.
    const targets = definedTargets();
    expect(targets).toEqual(["search", "frameworks"]);
  });

  it("never targets an element outside the allowed anchor set", () => {
    const targets = definedTargets();
    for (const target of targets) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("includes a non-anchored welcome step (no target)", () => {
    const welcomeSteps = viewComplianceTour.steps.filter(
      (step) => step.target === undefined,
    );
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the compliance route and component trees for the tour:check gate", () => {
    expect(viewComplianceTour.coversFiles).toContain(
      "ui/app/(prowler)/compliance/**",
    );
    expect(viewComplianceTour.coversFiles).toContain(
      "ui/components/compliance/**",
    );
  });
});

describe("createViewComplianceTourStepHandlers", () => {
  const makeHandlers = (overrides?: {
    resetSearch?: () => boolean;
    openFirstFramework?: () => void;
  }) =>
    createViewComplianceTourStepHandlers({
      resetSearch: overrides?.resetSearch ?? vi.fn(() => true),
      openFirstFramework: overrides?.openFirstFramework ?? vi.fn(),
    });

  it("resets the search and waits for the frameworks anchor before advancing", async () => {
    // An empty search result unmounts every card (anchor included); resetting first
    // guarantees the next step has an element to highlight.
    const resetSearch = vi.fn(() => true);
    const waitForStep = vi
      .fn()
      .mockResolvedValue(document.createElement("div"));
    const handlers = makeHandlers({ resetSearch });

    await handlers.search?.onNext?.({ waitForStep });

    expect(resetSearch).toHaveBeenCalledTimes(1);
    expect(waitForStep).toHaveBeenCalledWith("frameworks");
  });

  it("does not wait for frameworks when no card can render", async () => {
    const resetSearch = vi.fn(() => false);
    const waitForStep = vi.fn();
    const handlers = makeHandlers({ resetSearch });

    await handlers.search?.onNext?.({ waitForStep });

    expect(waitForStep).not.toHaveBeenCalled();
  });

  it("opens the first framework when leaving the last step", async () => {
    const openFirstFramework = vi.fn();
    const waitForStep = vi.fn();
    const handlers = makeHandlers({ openFirstFramework });

    await handlers.frameworks?.onNext?.({ waitForStep });

    expect(openFirstFramework).toHaveBeenCalledTimes(1);
    expect(waitForStep).not.toHaveBeenCalled();
  });
});
