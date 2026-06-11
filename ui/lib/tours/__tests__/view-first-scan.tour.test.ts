import { describe, expect, it } from "vitest";

import {
  buildViewFirstScanTour,
  viewFirstScanTour,
  type ViewFirstScanTourTarget,
} from "../view-first-scan.tour";

// These carry a `data-tour-id` in the UI; the welcome step has no target.
const ALLOWED_TARGETS = ["in-progress", "launch", "tabs"] as const;

const definedTargets = (tour = viewFirstScanTour): ViewFirstScanTourTarget[] =>
  tour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ViewFirstScanTourTarget => target !== undefined,
    );

describe("viewFirstScanTour shape (default, no running scan)", () => {
  it("declares the view-first-scan id", () => {
    expect(viewFirstScanTour.id).toBe("view-first-scan");
  });

  it("declares a positive integer version", () => {
    expect(Number.isInteger(viewFirstScanTour.version)).toBe(true);
    expect(viewFirstScanTour.version).toBeGreaterThan(0);
  });

  it("anchors exactly the launch and tabs steps, in that order", () => {
    expect(definedTargets()).toEqual(["launch", "tabs"]);
  });

  it("never targets an element outside the allowed anchor set", () => {
    for (const target of definedTargets()) {
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

  it("is the build output for the no-running-scan case", () => {
    // The registry's default flow uses this variant; the scans page rebuilds live.
    expect(definedTargets(buildViewFirstScanTour(false))).toEqual([
      "launch",
      "tabs",
    ]);
  });
});

describe("buildViewFirstScanTour with a running scan", () => {
  const tour = buildViewFirstScanTour(true);

  it("anchors the in-progress row first, then launch (no tabs step)", () => {
    // The tabs are mentioned in the in-progress step's copy instead of a separate step.
    expect(definedTargets(tour)).toEqual(["in-progress", "launch"]);
  });

  it("shares the same id and version as the default variant", () => {
    expect(tour.id).toBe(viewFirstScanTour.id);
    expect(tour.version).toBe(viewFirstScanTour.version);
  });

  it("never targets an element outside the allowed anchor set", () => {
    for (const target of definedTargets(tour)) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("keeps a non-anchored welcome step", () => {
    expect(
      tour.steps.filter((step) => step.target === undefined).length,
    ).toBeGreaterThanOrEqual(1);
  });
});
