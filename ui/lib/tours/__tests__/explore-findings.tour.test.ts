import { describe, expect, it } from "vitest";

import {
  exploreFindingsTour,
  type ExploreFindingsTourTarget,
} from "../explore-findings.tour";

// Only these two carry a `data-tour-id` in the UI; welcome step has no target.
const ALLOWED_TARGETS = ["filters", "table"] as const;

const definedTargets = (): ExploreFindingsTourTarget[] =>
  exploreFindingsTour.steps
    .map((step) => step.target)
    .filter(
      (target): target is ExploreFindingsTourTarget => target !== undefined,
    );

describe("exploreFindingsTour shape", () => {
  it("declares the explore-findings id", () => {
    expect(exploreFindingsTour.id).toBe("explore-findings");
  });

  it("declares a positive integer version", () => {
    expect(Number.isInteger(exploreFindingsTour.version)).toBe(true);
    expect(exploreFindingsTour.version).toBeGreaterThan(0);
  });

  it("anchors filters before table, in that order", () => {
    const targets = definedTargets();
    // filters mounts immediately; table appears after Suspense, so order matters
    expect(targets).toEqual(["filters", "table"]);
  });

  it("never targets an element outside the allowed anchor set", () => {
    const targets = definedTargets();
    for (const target of targets) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("includes a non-anchored welcome step (no target)", () => {
    const welcomeSteps = exploreFindingsTour.steps.filter(
      (step) => step.target === undefined,
    );
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the findings route and component trees for the tour:check gate", () => {
    expect(exploreFindingsTour.coversFiles).toContain(
      "ui/app/(prowler)/findings/**",
    );
    expect(exploreFindingsTour.coversFiles).toContain(
      "ui/components/findings/**",
    );
  });
});
