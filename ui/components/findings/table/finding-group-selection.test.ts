import { describe, expect, it } from "vitest";

import { canMuteFindingGroup } from "./finding-group-selection";

describe("canMuteFindingGroup", () => {
  it("returns false when impacted resources is zero", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 0,
        resourcesTotal: 2,
        mutedCount: 0,
      }),
    ).toBe(false);
  });

  it("returns false when all resources are already muted", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 3,
        resourcesTotal: 3,
        mutedCount: 3,
      }),
    ).toBe(false);
  });

  it("returns false when all failing resources are muted even if PASS resources exist", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 2,
        resourcesTotal: 5,
        mutedCount: 2,
      }),
    ).toBe(false);
  });

  it("returns true when the group still has failing resources to mute", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 2,
        resourcesTotal: 5,
        mutedCount: 1,
      }),
    ).toBe(true);
  });
});
