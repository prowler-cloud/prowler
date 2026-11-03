import { describe, expect, it, vi } from "vitest";

vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

import { getFindingGroupResources } from "@/actions/finding-groups";

import { SAMPLE_ACCOUNT, SAMPLE_CHECKS } from "./sample-dataset";
import { filterSampleFindingGroups } from "./sample-findings";
import { SAMPLE_STATUS } from "./sample-overview";

describe("sample finding filters", () => {
  it("shows passing sample findings reached from the Overview PASS segment", () => {
    // Given
    expect(SAMPLE_STATUS.pass).toBeGreaterThan(0);

    // When
    const result = filterSampleFindingGroups({ "filter[status__in]": "PASS" });

    // Then
    expect(result.groups.length).toBeGreaterThan(0);
    expect(result.groups.every((group) => group.status === "PASS")).toBe(true);
    expect(
      result.groups.reduce((total, group) => total + (group.passCount ?? 0), 0),
    ).toBe(SAMPLE_STATUS.pass);
    expect(result.groups.every((group) => group.failCount === 0)).toBe(true);
    expect(result.resourceFilters).toEqual({ "filter[status__in]": "PASS" });
  });

  it("keeps both outcomes without a status filter and limits FAIL drill-downs", () => {
    const all = filterSampleFindingGroups({});
    const failed = filterSampleFindingGroups({ "filter[status__in]": "FAIL" });

    expect(
      all.groups.reduce((total, group) => total + group.resourcesTotal, 0),
    ).toBe(SAMPLE_STATUS.pass + SAMPLE_STATUS.fail);
    expect(failed.groups.every((group) => group.passCount === 0)).toBe(true);
    expect(failed.resourceFilters).toEqual({ "filter[status__in]": "FAIL" });
    expect(
      filterSampleFindingGroups({ "filter[status__in]": "MANUAL" }).groups,
    ).toEqual([]);
  });

  it("limits the table to the check opened from the resource drawer", () => {
    const result = filterSampleFindingGroups({
      "filter[check_id__in]": "s3_bucket_public_access",
    });
    expect(result.groups.map((group) => group.checkId)).toEqual([
      "s3_bucket_public_access",
    ]);
  });

  it("searches sample groups by title and check ID", () => {
    const result = filterSampleFindingGroups({
      "filter[search]": "S3_BUCKET_PUBLIC_ACCESS",
    });
    expect(result.groups.map((group) => group.checkId)).toEqual([
      "s3_bucket_public_access",
    ]);
    expect(
      filterSampleFindingGroups({ "filter[search]": "no-such-check" }).groups,
    ).toEqual([]);
  });

  it("honors the check and severity column sorting controls", () => {
    const sorted = filterSampleFindingGroups({ sort: "check_id" });
    expect(sorted.groups.map((group) => group.checkId)).toEqual(
      SAMPLE_CHECKS.map((check) => check.checkId).sort(),
    );
    const ranks: Record<string, number> = {
      informational: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    const descending = filterSampleFindingGroups({
      sort: "-severity",
    }).groups.map((group) => ranks[group.severity]);
    expect(descending).toEqual([...descending].sort((a, b) => b - a));
  });

  it("applies the resource search entered in an expanded sample group", async () => {
    // Given / When
    const result = await getFindingGroupResources({
      checkId: "s3_bucket_public_access",
      pageSize: 100,
      filters: {
        "filter[scan]": SAMPLE_ACCOUNT.scanId,
        "filter[name__icontains]": "ACME-CUSTOMER-EXPORTS",
      },
    });

    // Then
    expect(result.data).toHaveLength(1);
    expect(result.meta.pagination.count).toBe(1);
  });
});
