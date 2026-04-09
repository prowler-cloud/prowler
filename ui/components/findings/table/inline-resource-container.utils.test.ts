import { describe, expect, it } from "vitest";

import type { FindingGroupRow } from "@/types";

import {
  getFilteredFindingGroupResourceCount,
  getFindingGroupSkeletonCount,
  isFailOnlyStatusFilter,
} from "./inline-resource-container.utils";

function makeGroup(
  overrides?: Partial<FindingGroupRow>,
): FindingGroupRow {
  return {
    id: "group-1",
    rowType: "group",
    checkId: "check-1",
    checkTitle: "Test finding group",
    severity: "high",
    status: "FAIL",
    resourcesTotal: 20,
    resourcesFail: 6,
    newCount: 0,
    changedCount: 0,
    mutedCount: 0,
    providers: ["aws"],
    updatedAt: "2026-04-09T00:00:00Z",
    ...overrides,
  };
}

describe("isFailOnlyStatusFilter", () => {
  it("returns true when filter[status__in] only contains FAIL", () => {
    expect(
      isFailOnlyStatusFilter({
        "filter[status__in]": "FAIL",
      }),
    ).toBe(true);
  });

  it("returns false when filter[status__in] includes more than FAIL", () => {
    expect(
      isFailOnlyStatusFilter({
        "filter[status__in]": "FAIL,PASS",
      }),
    ).toBe(false);
  });

  it("returns true when filter[status] is FAIL", () => {
    expect(
      isFailOnlyStatusFilter({
        "filter[status]": "FAIL",
      }),
    ).toBe(true);
  });
});

describe("getFindingGroupSkeletonCount", () => {
  it("returns zero filtered resources when FAIL is the only active status and none fail", () => {
    expect(
      getFilteredFindingGroupResourceCount(
        makeGroup({ resourcesFail: 0, resourcesTotal: 4 }),
        { "filter[status__in]": "FAIL" },
      ),
    ).toBe(0);
  });

  it("uses the total resource count when FAIL is not the only active status", () => {
    expect(getFindingGroupSkeletonCount(makeGroup(), {}, 7)).toBe(7);
  });

  it("uses the failing resource count when FAIL is the only active status", () => {
    expect(
      getFindingGroupSkeletonCount(
        makeGroup(),
        { "filter[status__in]": "FAIL" },
        7,
      ),
    ).toBe(6);
  });

  it("still caps the skeleton count to the configured maximum", () => {
    expect(
      getFindingGroupSkeletonCount(
        makeGroup({ resourcesFail: 15 }),
        { "filter[status__in]": "FAIL" },
        7,
      ),
    ).toBe(7);
  });

  it("reserves one skeleton row when the filtered resource count is zero", () => {
    expect(
      getFindingGroupSkeletonCount(
        makeGroup({ resourcesFail: 0, resourcesTotal: 0 }),
        { "filter[status__in]": "FAIL" },
        7,
      ),
    ).toBe(1);
  });
});
