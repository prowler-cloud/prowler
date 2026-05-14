import { describe, expect, it } from "vitest";

import { canMuteFindingGroup } from "./finding-group-selection";

describe("canMuteFindingGroup", () => {
  it("returns false when impacted resources is zero", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 0,
        muted: false,
      }),
    ).toBe(false);
  });

  it("returns false when the explicit muted flag marks the group as fully muted", () => {
    expect(
      canMuteFindingGroup({
        resourcesFail: 3,
        muted: true,
      }),
    ).toBe(false);
  });

  it("returns false when legacy counters indicate all failing resources are muted", () => {
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
        muted: false,
      }),
    ).toBe(true);
  });
});
