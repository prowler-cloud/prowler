import { describe, expect, it } from "vitest";

import {
  addProviderTour,
  type AddProviderTourTarget,
} from "../add-provider.tour";

// The set of anchored step targets the tour is allowed to reference. Only these
// two carry a `data-tour-id` in the UI source; the welcome step has no target.
const ALLOWED_TARGETS = ["trigger", "provider-type"] as const;

const definedTargets = (): AddProviderTourTarget[] =>
  addProviderTour.steps
    .map((step) => step.target)
    .filter((target): target is AddProviderTourTarget => target !== undefined);

describe("addProviderTour shape", () => {
  it("declares the add-provider id", () => {
    // Given / When / Then - the tour id is the registry/anchor contract key
    expect(addProviderTour.id).toBe("add-provider");
  });

  it("declares a positive integer version", () => {
    // Given / When / Then - version drives the per-tour completion record key
    expect(Number.isInteger(addProviderTour.version)).toBe(true);
    expect(addProviderTour.version).toBeGreaterThan(0);
  });

  it("includes a trigger step and a provider-type step", () => {
    // Given - the anchored step targets present in the tour
    const targets = definedTargets();

    // Then - both anchored stages exist
    expect(targets).toContain("trigger");
    expect(targets).toContain("provider-type");
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
    const welcomeSteps = addProviderTour.steps.filter(
      (step) => step.target === undefined,
    );

    // Then - at least one targetless step exists for the welcome modal
    expect(welcomeSteps.length).toBeGreaterThanOrEqual(1);
  });

  it("covers the providers component tree for the tour:check gate", () => {
    // Given / When / Then - coversFiles scopes the CI drift check to providers
    expect(addProviderTour.coversFiles).toContain("ui/components/providers/**");
  });
});
