import { describe, expect, it } from "vitest";

import {
  viewFirstScanTour,
  type ViewFirstScanTourTarget,
} from "../view-first-scan.tour";

// The set of anchored step targets the tour is allowed to reference. Only these
// two carry a `data-tour-id` in the UI source; the welcome step has no target.
const ALLOWED_TARGETS = ["launch", "tabs"] as const;

const definedTargets = (): ViewFirstScanTourTarget[] =>
  viewFirstScanTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ViewFirstScanTourTarget => target !== undefined,
    );

describe("viewFirstScanTour shape", () => {
  it("declares the view-first-scan id", () => {
    // Given / When / Then - the tour id is the registry/anchor contract key
    expect(viewFirstScanTour.id).toBe("view-first-scan");
  });

  it("declares a positive integer version", () => {
    // Given / When / Then - version drives the per-tour completion record key
    expect(Number.isInteger(viewFirstScanTour.version)).toBe(true);
    expect(viewFirstScanTour.version).toBeGreaterThan(0);
  });

  it("anchors exactly the launch and tabs steps, in that order", () => {
    // Given - every defined anchored target in document order
    const targets = definedTargets();

    // Then - shallow tour orients via launch then tabs only
    expect(targets).toEqual(["launch", "tabs"]);
  });

  it("never targets an element outside the allowed anchor set", () => {
    // Given - every defined target across all steps
    const targets = definedTargets();

    // Then - no target escapes the two anchors guarded by tour:check
    for (const target of targets) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("includes a non-anchored welcome step (no target)", () => {
    // Given - the modal welcome step carries no target
    const welcomeSteps = viewFirstScanTour.steps.filter(
      (step) => step.target === undefined,
    );

    // Then - at least one targetless step exists for the welcome modal
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the scans route and component trees for the tour:check gate", () => {
    // Given / When / Then - coversFiles scopes the CI drift check to scans
    expect(viewFirstScanTour.coversFiles).toContain(
      "ui/app/(prowler)/scans/**",
    );
    expect(viewFirstScanTour.coversFiles).toContain("ui/components/scans/**");
  });
});
