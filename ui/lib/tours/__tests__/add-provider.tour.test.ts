import { describe, expect, it } from "vitest";

import {
  addProviderTour,
  type AddProviderTourTarget,
} from "../add-provider.tour";

// The set of anchored step targets the tour is allowed to reference. Only
// `trigger` carries a `data-tour-id` in the UI source; the welcome step has no
// target. The tour ends at the Add Provider button and never anchors inside the
// wizard, so it cannot overlay the Radix dialog and close it mid-flow.
const ALLOWED_TARGETS = ["trigger"] as const;

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

  it("includes a trigger step as the only anchored step", () => {
    // Given - the anchored step targets present in the tour
    const targets = definedTargets();

    // Then - the trigger anchor exists and is the single anchored stage
    expect(targets).toContain("trigger");
    expect(targets).toHaveLength(1);
  });

  it("never anchors inside the provider wizard (no provider-type step)", () => {
    // Given - the anchored step targets present in the tour
    const targets = definedTargets();

    // Then - the wizard-internal anchor is gone so the driver overlay never
    // sits on top of the Radix dialog and closes it mid-flow.
    expect(targets).not.toContain("provider-type");
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
