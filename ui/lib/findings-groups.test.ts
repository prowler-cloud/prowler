import { describe, expect, it } from "vitest";

import type { FindingGroupRow } from "@/types";

import { getFindingGroupDelta, isFindingGroupMuted } from "./findings-groups";

function makeGroup(overrides?: Partial<FindingGroupRow>): FindingGroupRow {
  return {
    id: "group-1",
    rowType: "group",
    checkId: "check-1",
    checkTitle: "Test finding group",
    severity: "high",
    status: "FAIL",
    muted: false,
    resourcesTotal: 5,
    resourcesFail: 3,
    newCount: 0,
    changedCount: 0,
    mutedCount: 0,
    providers: ["aws"],
    updatedAt: "2026-04-10T00:00:00Z",
    ...overrides,
  };
}

describe("isFindingGroupMuted", () => {
  it("should prefer the explicit muted flag from the API", () => {
    expect(
      isFindingGroupMuted(
        makeGroup({
          muted: true,
          mutedCount: 0,
          resourcesFail: 3,
          resourcesTotal: 5,
        }),
      ),
    ).toBe(true);
  });

  it("should fall back to legacy counters when muted is not available", () => {
    expect(
      isFindingGroupMuted(
        makeGroup({
          muted: undefined,
          mutedCount: 3,
          resourcesFail: 3,
        }),
      ),
    ).toBe(true);
  });
});

describe("getFindingGroupDelta", () => {
  it("should return new when the muted breakdown contains new findings", () => {
    expect(
      getFindingGroupDelta(
        makeGroup({
          newCount: 0,
          changedCount: 0,
          newFailMutedCount: 1,
        }),
      ),
    ).toBe("new");
  });

  it("should return changed when only changed breakdown counters are present", () => {
    expect(
      getFindingGroupDelta(
        makeGroup({
          newCount: 0,
          changedCount: 0,
          changedManualMutedCount: 2,
        }),
      ),
    ).toBe("changed");
  });

  it("should prioritize new over changed when both breakdowns are present", () => {
    expect(
      getFindingGroupDelta(
        makeGroup({
          newCount: 0,
          changedCount: 0,
          newPassCount: 1,
          changedFailCount: 3,
        }),
      ),
    ).toBe("new");
  });

  it("should fall back to legacy counters when breakdowns are missing", () => {
    expect(
      getFindingGroupDelta(
        makeGroup({
          newCount: 1,
          changedCount: 0,
        }),
      ),
    ).toBe("new");
  });
});
