import { describe, expect, it, vi } from "vitest";

vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

import { getFindingGroupResources } from "@/actions/finding-groups";

import { SAMPLE_ACCOUNT, SAMPLE_CHECKS } from "./sample-dataset";
import { filterSampleFindingGroups } from "./sample-findings";
import { SAMPLE_STATUS } from "./sample-overview";
import { SAMPLE_FINDINGS } from "./sample-records";

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

  it("narrows to new failures when the Overview link asks for them", () => {
    // Given
    const newChecks = SAMPLE_CHECKS.filter((check) => check.newFailed > 0);

    // When
    const result = filterSampleFindingGroups({
      "filter[status__in]": "FAIL",
      "filter[delta]": "new",
    });

    // Then
    expect(result.groups.map((group) => group.checkId).sort()).toEqual(
      newChecks.map((check) => check.checkId).sort(),
    );
    expect(result.resourceFilters).toEqual({
      "filter[status__in]": "FAIL",
      "filter[delta]": "new",
    });
  });

  it("counts only the resources in the selected region and type", () => {
    // Given
    const [{ resource }] = SAMPLE_FINDINGS;
    const matching = SAMPLE_FINDINGS.filter(
      (finding) =>
        finding.resource.region === resource.region &&
        finding.resource.type === resource.type,
    );

    // When
    const result = filterSampleFindingGroups({
      "filter[region__in]": resource.region,
      "filter[resource_type__in]": resource.type,
    });

    // Then
    expect(
      result.groups.reduce(
        (total, group) =>
          total + (group.failCount ?? 0) + (group.passCount ?? 0),
        0,
      ),
    ).toBe(matching.length);
  });

  it("keeps the sample account for its provider and drops muted-only views", () => {
    expect(
      filterSampleFindingGroups({ "filter[provider_type__in]": "aws" }).groups,
    ).toHaveLength(SAMPLE_CHECKS.length);
    expect(
      filterSampleFindingGroups({ "filter[provider_type__in]": "azure" })
        .groups,
    ).toHaveLength(0);
    expect(
      filterSampleFindingGroups({ "filter[muted]": "true" }).groups,
    ).toHaveLength(0);
  });

  it("applies the group's region filter to its expanded resources", async () => {
    // Given
    const check = "s3_bucket_public_access";
    const region = SAMPLE_FINDINGS.find(
      (finding) => finding.check.checkId === check,
    )!.resource.region;

    // When
    const result = await getFindingGroupResources({
      checkId: check,
      pageSize: 100,
      filters: {
        "filter[scan]": SAMPLE_ACCOUNT.scanId,
        "filter[region__in]": region,
      },
    });

    // Then
    expect(result.data.length).toBeGreaterThan(0);
    expect(
      result.data.every(
        (row: { attributes: { resource: { region: string } } }) =>
          row.attributes.resource.region === region,
      ),
    ).toBe(true);
  });

  it("matches the date filter against the sample scan's day", () => {
    const scanDay = SAMPLE_ACCOUNT.scannedAt.slice(0, 10);

    expect(
      filterSampleFindingGroups({ "filter[inserted_at]": scanDay }).groups,
    ).toHaveLength(SAMPLE_CHECKS.length);
    expect(
      filterSampleFindingGroups({ "filter[inserted_at]": "2020-01-01" }).groups,
    ).toHaveLength(0);
  });
});
