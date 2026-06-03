import { describe, expect, it } from "vitest";

import {
  viewComplianceTour,
  type ViewComplianceTourTarget,
} from "../view-compliance.tour";

// The set of anchored step targets the tour is allowed to reference. Only these
// two carry a `data-tour-id` in the UI source; the welcome step has no target.
const ALLOWED_TARGETS = ["frameworks", "search"] as const;

const definedTargets = (): ViewComplianceTourTarget[] =>
  viewComplianceTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ViewComplianceTourTarget => target !== undefined,
    );

describe("viewComplianceTour shape", () => {
  it("declares the view-compliance id", () => {
    // Given / When / Then - the tour id is the registry/anchor contract key
    expect(viewComplianceTour.id).toBe("view-compliance");
  });

  it("declares a positive integer version", () => {
    // Given / When / Then - version drives the per-tour completion record key
    expect(Number.isInteger(viewComplianceTour.version)).toBe(true);
    expect(viewComplianceTour.version).toBeGreaterThan(0);
  });

  it("anchors exactly the frameworks and search steps, in that order", () => {
    // Given - every defined anchored target in document order
    const targets = definedTargets();

    // Then - shallow tour orients via frameworks then search only
    expect(targets).toEqual(["frameworks", "search"]);
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
    const welcomeSteps = viewComplianceTour.steps.filter(
      (step) => step.target === undefined,
    );

    // Then - at least one targetless step exists for the welcome modal
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the compliance route and component trees for the tour:check gate", () => {
    // Given / When / Then - coversFiles scopes the CI drift check to compliance
    expect(viewComplianceTour.coversFiles).toContain(
      "ui/app/(prowler)/compliance/**",
    );
    expect(viewComplianceTour.coversFiles).toContain(
      "ui/components/compliance/**",
    );
  });
});
