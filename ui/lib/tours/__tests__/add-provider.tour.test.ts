import { describe, expect, it } from "vitest";

import {
  addProviderTour,
  type AddProviderTourTarget,
} from "../add-provider.tour";

// These carry a `data-tour-id` in the UI; the welcome step has no target.
const ALLOWED_TARGETS = ["trigger", "provider-type", "wizard-body"] as const;

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

  it("includes the trigger, provider-type, and wizard-body steps in order", () => {
    const targets = definedTargets();
    expect(targets).toEqual(["trigger", "provider-type", "wizard-body"]);
  });

  it("marks every anchored step as autoAdvance (no Next button)", () => {
    // All anchored steps advance imperatively from the UI (clicking the real
    // "Add a Provider" button, picking a type, etc.), so none renders a Next button.
    const byTarget = (target: AddProviderTourTarget) =>
      addProviderTour.steps.find((step) => step.target === target);

    expect(byTarget("trigger")?.autoAdvance).toBe(true);
    expect(byTarget("provider-type")?.autoAdvance).toBe(true);
    expect(byTarget("wizard-body")?.autoAdvance).toBe(true);
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
