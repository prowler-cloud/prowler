import { describe, expect, it } from "vitest";

import type { OnboardingFlow } from "@/lib/onboarding";

import { getSequenceProgress } from "../onboarding-sequence-banner.logic";

// Minimal flow fixtures: the progress helper only reads id/order/title/route
// and the optional dataRequirementHint, so a flat shape is sufficient.
const buildFlow = (overrides: Partial<OnboardingFlow>): OnboardingFlow =>
  ({
    id: overrides.id ?? "flow",
    order: overrides.order ?? 1,
    title: overrides.title ?? "Title",
    description: overrides.description ?? "Description",
    route: overrides.route ?? "/route",
    tour: overrides.tour ?? { id: "t", version: 1, coversFiles: [], steps: [] },
    dataRequirementHint: overrides.dataRequirementHint,
  }) as OnboardingFlow;

const flows: OnboardingFlow[] = [
  buildFlow({ id: "a", order: 1, title: "First", route: "/a" }),
  buildFlow({
    id: "b",
    order: 2,
    title: "Second",
    route: "/b",
    dataRequirementHint: "needs a scan",
  }),
  buildFlow({ id: "c", order: 3, title: "Third", route: "/c" }),
];

describe("getSequenceProgress", () => {
  it("computes the index, total, current flow, and next flow for a middle step", () => {
    // Given - the sequence points at the second flow
    // When
    const progress = getSequenceProgress("b", flows);

    // Then - 0-based index 1 of 3, current is b, next is c
    expect(progress).not.toBeNull();
    expect(progress?.index).toBe(1);
    expect(progress?.total).toBe(3);
    expect(progress?.flow.id).toBe("b");
    expect(progress?.nextFlow?.id).toBe("c");
  });

  it("returns a null nextFlow on the last step", () => {
    // Given - the sequence points at the final flow
    // When
    const progress = getSequenceProgress("c", flows);

    // Then - index 2 of 3, no next flow
    expect(progress?.index).toBe(2);
    expect(progress?.total).toBe(3);
    expect(progress?.nextFlow).toBeNull();
  });

  it("returns null when the currentFlowId is unknown or null", () => {
    // Given / When / Then - an id not in the registry or a null id yields null
    expect(getSequenceProgress("missing", flows)).toBeNull();
    expect(getSequenceProgress(null, flows)).toBeNull();
  });

  it("exposes the data requirement hint of the current flow when present", () => {
    // Given - flow b carries a data hint, flow a does not
    // When
    const withHint = getSequenceProgress("b", flows);
    const withoutHint = getSequenceProgress("a", flows);

    // Then
    expect(withHint?.flow.dataRequirementHint).toBe("needs a scan");
    expect(withoutHint?.flow.dataRequirementHint).toBeUndefined();
  });
});
