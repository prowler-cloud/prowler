import { describe, expect, it } from "vitest";

import {
  viewFirstScanTour,
  type ViewFirstScanTourTarget,
} from "../view-first-scan.tour";

// Only these two carry a `data-tour-id` in the UI; welcome step has no target.
const ALLOWED_TARGETS = ["launch", "tabs"] as const;

const definedTargets = (): ViewFirstScanTourTarget[] =>
  viewFirstScanTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ViewFirstScanTourTarget => target !== undefined,
    );

describe("viewFirstScanTour shape", () => {
  it("declares the view-first-scan id", () => {
    expect(viewFirstScanTour.id).toBe("view-first-scan");
  });

  it("declares a positive integer version", () => {
    expect(Number.isInteger(viewFirstScanTour.version)).toBe(true);
    expect(viewFirstScanTour.version).toBeGreaterThan(0);
  });

  it("anchors exactly the launch and tabs steps, in that order", () => {
    const targets = definedTargets();
    expect(targets).toEqual(["launch", "tabs"]);
  });

  it("never targets an element outside the allowed anchor set", () => {
    const targets = definedTargets();
    for (const target of targets) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("includes a non-anchored welcome step (no target)", () => {
    const welcomeSteps = viewFirstScanTour.steps.filter(
      (step) => step.target === undefined,
    );
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the scans route and component trees for the tour:check gate", () => {
    expect(viewFirstScanTour.coversFiles).toContain(
      "ui/app/(prowler)/scans/**",
    );
    expect(viewFirstScanTour.coversFiles).toContain("ui/components/scans/**");
  });
});
