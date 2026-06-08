import { describe, expect, it } from "vitest";

import {
  addProviderTour,
  type AddProviderTourTarget,
} from "../add-provider.tour";

// Only these two carry a `data-tour-id` in the UI; welcome step has no target.
const ALLOWED_TARGETS = ["trigger", "provider-type"] as const;

const definedTargets = (): AddProviderTourTarget[] =>
  addProviderTour.steps
    .map((step) => step.target)
    .filter((target): target is AddProviderTourTarget => target !== undefined);

describe("addProviderTour shape", () => {
  it("declares the add-provider id", () => {
    expect(addProviderTour.id).toBe("add-provider");
  });

  it("declares a positive integer version", () => {
    expect(Number.isInteger(addProviderTour.version)).toBe(true);
    expect(addProviderTour.version).toBeGreaterThan(0);
  });

  it("includes a trigger step and a provider-type step", () => {
    const targets = definedTargets();
    expect(targets).toContain("trigger");
    expect(targets).toContain("provider-type");
  });

  it("never targets an element outside the allowed anchor set", () => {
    const targets = definedTargets();
    for (const target of targets) {
      expect(ALLOWED_TARGETS).toContain(target);
    }
  });

  it("includes a non-anchored welcome step (no target)", () => {
    const welcomeSteps = addProviderTour.steps.filter(
      (step) => step.target === undefined,
    );
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the providers component tree for the tour:check gate", () => {
    expect(addProviderTour.coversFiles).toContain("ui/components/providers/**");
  });
});
