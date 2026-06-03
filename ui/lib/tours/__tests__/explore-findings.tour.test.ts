import { describe, expect, it } from "vitest";

import {
  exploreFindingsTour,
  type ExploreFindingsTourTarget,
} from "../explore-findings.tour";

// The set of anchored step targets the tour is allowed to reference. Only these
// two carry a `data-tour-id` in the UI source; the welcome step has no target.
const ALLOWED_TARGETS = ["filters", "table"] as const;

const definedTargets = (): ExploreFindingsTourTarget[] =>
  exploreFindingsTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ExploreFindingsTourTarget => target !== undefined,
    );

describe("exploreFindingsTour shape", () => {
  it("declares the explore-findings id", () => {
    // Given / When / Then - the tour id is the registry/anchor contract key
    expect(exploreFindingsTour.id).toBe("explore-findings");
  });

  it("declares a positive integer version", () => {
    // Given / When / Then - version drives the per-tour completion record key
    expect(Number.isInteger(exploreFindingsTour.version)).toBe(true);
    expect(exploreFindingsTour.version).toBeGreaterThan(0);
  });

  it("anchors filters before table, in that order", () => {
    // Given - every defined anchored target in document order
    const targets = definedTargets();

    // Then - filters mounts immediately; table appears after Suspense, so the
    // order matters and filters must precede table.
    expect(targets).toEqual(["filters", "table"]);
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
    const welcomeSteps = exploreFindingsTour.steps.filter(
      (step) => step.target === undefined,
    );

    // Then - at least one targetless step exists for the welcome modal
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the findings route and component trees for the tour:check gate", () => {
    // Given / When / Then - coversFiles scopes the CI drift check to findings
    expect(exploreFindingsTour.coversFiles).toContain(
      "ui/app/(prowler)/findings/**",
    );
    expect(exploreFindingsTour.coversFiles).toContain(
      "ui/components/findings/**",
    );
  });
});
