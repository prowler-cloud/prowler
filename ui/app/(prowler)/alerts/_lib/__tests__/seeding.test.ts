import { describe, expect, it } from "vitest";

import {
  canSeedAlertFromFindingsFilters,
  toPortableAlertFilterBag,
} from "../seeding";

describe("canSeedAlertFromFindingsFilters", () => {
  it("should accept status, muted, and scan filters as real Findings filters", () => {
    // Given
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[muted]": "false",
      "filter[scan__in]": "scan-1",
    };

    // When
    const result = canSeedAlertFromFindingsFilters(filterBag);

    // Then
    expect(result).toBe(true);
  });

  it("should reject sort and pagination without a real filter", () => {
    // Given
    const filterBag = {
      sort: "-inserted_at",
      page: "2",
      pageSize: "50",
    };

    // When
    const result = canSeedAlertFromFindingsFilters(filterBag);

    // Then
    expect(result).toBe(false);
  });

  it("should accept finding group id filters because the backend treats them as portable", () => {
    // Given
    const filterBag = {
      "filter[finding_group_id]": "group-1",
    };

    // When
    const result = canSeedAlertFromFindingsFilters(filterBag);

    // Then
    expect(result).toBe(true);
  });

  it("should accept at least one supported portable finding filter", () => {
    // Given
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[severity__in]": "critical,high",
    };

    // When
    const result = canSeedAlertFromFindingsFilters(filterBag);

    // Then
    expect(result).toBe(true);
  });
});

describe("toPortableAlertFilterBag", () => {
  it("should keep backend-compatible filters and drop UI-only filters", () => {
    // Given
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[muted]": "false",
      "filter[scan__in]": "scan-1",
      "filter[severity__in]": "critical,high",
      "filter[region__in]": "us-east-1",
      sort: "-inserted_at",
      page: "2",
    };

    // When
    const result = toPortableAlertFilterBag(filterBag);

    // Then
    expect(result).toEqual({
      "filter[severity__in]": "critical,high",
      "filter[region__in]": "us-east-1",
    });
  });

  it("should return an empty bag when only unsupported filters are selected", () => {
    // Given
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[muted]": "false",
      "filter[scan__in]": "scan-1",
    };

    // When
    const result = toPortableAlertFilterBag(filterBag);

    // Then
    expect(result).toEqual({});
  });
});
