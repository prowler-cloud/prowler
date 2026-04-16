import { describe, expect, it } from "vitest";

import type { FindingGroupRow } from "@/types";

import {
  getActiveStatusFilter,
  getFilteredFindingGroupDelta,
  getFindingGroupDelta,
  getFindingGroupImpactedCounts,
  isFindingGroupMuted,
} from "./findings-groups";

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

describe("getActiveStatusFilter", () => {
  it("returns null when no status filter is active", () => {
    expect(getActiveStatusFilter({})).toBeNull();
  });

  it("returns the single value from filter[status]", () => {
    const result = getActiveStatusFilter({ "filter[status]": "FAIL" });
    expect(result).toEqual(new Set(["FAIL"]));
  });

  it("returns the parsed set from filter[status__in]", () => {
    const result = getActiveStatusFilter({
      "filter[status__in]": "FAIL,MANUAL",
    });
    expect(result).toEqual(new Set(["FAIL", "MANUAL"]));
  });

  it("prefers filter[status] over filter[status__in] when both are present", () => {
    const result = getActiveStatusFilter({
      "filter[status]": "PASS",
      "filter[status__in]": "FAIL,MANUAL",
    });
    expect(result).toEqual(new Set(["PASS"]));
  });

  it("ignores unknown status values and returns null if nothing remains", () => {
    expect(
      getActiveStatusFilter({ "filter[status__in]": "UNKNOWN,FOO" }),
    ).toBeNull();
  });
});

describe("getFindingGroupImpactedCounts", () => {
  it("should fall back to pass and fail counts when resources total is zero", () => {
    // Given
    const group = makeGroup({
      resourcesTotal: 0,
      resourcesFail: 0,
      failCount: 3,
      passCount: 2,
      muted: false,
    });

    // When
    const result = getFindingGroupImpactedCounts(group);

    // Then
    expect(result).toEqual({ impacted: 3, total: 5 });
  });

  it("should include muted pass and fail counts in the denominator when the result is muted", () => {
    // Given
    const group = makeGroup({
      resourcesTotal: 0,
      resourcesFail: 0,
      failCount: 3,
      passCount: 2,
      failMutedCount: 4,
      passMutedCount: 1,
      muted: true,
    });

    // When
    const result = getFindingGroupImpactedCounts(group);

    // Then
    expect(result).toEqual({ impacted: 3, total: 10 });
  });

  it("should keep resource-based counts when resources total is available", () => {
    // Given
    const group = makeGroup({
      resourcesTotal: 6,
      resourcesFail: 4,
      failCount: 2,
      passCount: 1,
      failMutedCount: 5,
      passMutedCount: 3,
      muted: true,
    });

    // When
    const result = getFindingGroupImpactedCounts(group);

    // Then
    expect(result).toEqual({ impacted: 4, total: 6 });
  });
});

describe("getFilteredFindingGroupDelta", () => {
  it("falls back to the aggregate delta when no status filter is active", () => {
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newPassCount: 2,
        }),
        {},
      ),
    ).toBe("new");
  });

  it("ignores deltas that belong to filtered-out statuses", () => {
    // Filter is FAIL, but the only delta is a new PASS → should be hidden.
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newPassCount: 3,
        }),
        { "filter[status__in]": "FAIL" },
      ),
    ).toBe("none");
  });

  it("surfaces FAIL deltas when the filter is FAIL", () => {
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newFailCount: 1,
        }),
        { "filter[status]": "FAIL" },
      ),
    ).toBe("new");
  });

  it("counts muted breakdown counters towards the filtered status", () => {
    // A muted new FAIL still belongs to the FAIL bucket — a FAIL filter
    // should still light up the "new" indicator.
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newFailMutedCount: 1,
        }),
        { "filter[status]": "FAIL" },
      ),
    ).toBe("new");
  });

  it("sums multiple filtered statuses from filter[status__in]", () => {
    // Filter is FAIL+MANUAL, new delta is only in MANUAL → should still show.
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newManualCount: 1,
        }),
        { "filter[status__in]": "FAIL,MANUAL" },
      ),
    ).toBe("new");
  });

  it("prefers new over changed within the filtered status", () => {
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newFailCount: 1,
          changedFailCount: 2,
        }),
        { "filter[status]": "FAIL" },
      ),
    ).toBe("new");
  });

  it("returns changed when only changed counters match the filtered status", () => {
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newPassCount: 2, // filtered out
          changedFailCount: 1,
        }),
        { "filter[status]": "FAIL" },
      ),
    ).toBe("changed");
  });

  it("falls back to the aggregate delta when breakdowns are missing (legacy API)", () => {
    // No breakdown fields populated but legacy newCount is set. With a FAIL
    // filter active we cannot know which status bucket it belongs to, so we
    // fall back to showing the delta rather than silently hiding it.
    expect(
      getFilteredFindingGroupDelta(
        makeGroup({
          newCount: 1,
        }),
        { "filter[status]": "FAIL" },
      ),
    ).toBe("new");
  });
});
