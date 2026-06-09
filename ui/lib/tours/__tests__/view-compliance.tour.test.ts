import { describe, expect, it } from "vitest";

import {
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
