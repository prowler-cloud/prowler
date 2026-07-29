import { describe, expect, it, vi } from "vitest";

import {
  createExploreFindingsTourStepHandlers,
  exploreFindingsTour,
  type ExploreFindingsTourTarget,
} from "../explore-findings.tour";

// Only these carry a `data-tour-id` in the UI; welcome step has no target.
const ALLOWED_TARGETS = ["filters", "group", "resources"] as const;

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

  it("anchors filters, then the first group, then its resources, in that order", () => {
    const targets = definedTargets();
    // filters mounts immediately; group/resources appear after Suspense + drill-down, so order matters
    expect(targets).toEqual(["filters", "group", "resources"]);
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

describe("createExploreFindingsTourStepHandlers", () => {
  it("opens the first group and waits for the resources anchor before advancing", async () => {
    const openFirstGroup = vi.fn(() => true);
    const waitForStep = vi
      .fn()
      .mockResolvedValue(document.createElement("div"));
    const handlers = createExploreFindingsTourStepHandlers(openFirstGroup);

    await handlers.group?.onNext?.({ waitForStep });

    expect(openFirstGroup).toHaveBeenCalledTimes(1);
    expect(waitForStep).toHaveBeenCalledWith("resources");
  });

  it("does not wait for resources when no group can be opened", async () => {
    const openFirstGroup = vi.fn(() => false);
    const waitForStep = vi.fn();
    const handlers = createExploreFindingsTourStepHandlers(openFirstGroup);

    await handlers.group?.onNext?.({ waitForStep });

    expect(openFirstGroup).toHaveBeenCalledTimes(1);
    expect(waitForStep).not.toHaveBeenCalled();
  });

  it("registers a handler only for the group step", () => {
    const handlers = createExploreFindingsTourStepHandlers(() => true);

    expect(Object.keys(handlers)).toEqual(["group"]);
  });
});
