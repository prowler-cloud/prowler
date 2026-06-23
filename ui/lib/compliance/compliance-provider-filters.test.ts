import { describe, expect, it } from "vitest";

import {
  COMPLIANCE_PROVIDER_FILTER_KEYS,
  extractComplianceProviderFilters,
  hasComplianceProviderFilters,
} from "./compliance-provider-filters";

describe("COMPLIANCE_PROVIDER_FILTER_KEYS", () => {
  it("contains the three provider scope keys", () => {
    expect(COMPLIANCE_PROVIDER_FILTER_KEYS).toEqual([
      "filter[provider_type__in]",
      "filter[provider_id__in]",
      "filter[provider_groups__in]",
    ]);
  });
});

describe("hasComplianceProviderFilters", () => {
  for (const key of COMPLIANCE_PROVIDER_FILTER_KEYS) {
    it(`is true when ${key} is present (plain object)`, () => {
      expect(hasComplianceProviderFilters({ [key]: "abc" })).toBe(true);
    });
  }

  it("is true when reading from URLSearchParams", () => {
    const params = new URLSearchParams();
    params.set("filter[provider_groups__in]", "g1,g2");
    expect(hasComplianceProviderFilters(params)).toBe(true);
  });

  it("is false for scanId / region / unrelated params", () => {
    expect(
      hasComplianceProviderFilters({
        scanId: "scan-1",
        "filter[region__in]": "eu-west-1",
      }),
    ).toBe(false);
  });

  it("treats empty / whitespace values as absent", () => {
    expect(
      hasComplianceProviderFilters({
        "filter[provider_type__in]": "",
        "filter[provider_id__in]": "   ",
      }),
    ).toBe(false);
  });

  it("is false for an empty object", () => {
    expect(hasComplianceProviderFilters({})).toBe(false);
  });
});

describe("extractComplianceProviderFilters", () => {
  it("returns only the present, non-empty provider keys", () => {
    expect(
      extractComplianceProviderFilters({
        "filter[provider_type__in]": "aws,gcp",
        "filter[provider_id__in]": "",
        scanId: "scan-1",
        "filter[region__in]": "eu-west-1",
      }),
    ).toEqual({ "filter[provider_type__in]": "aws,gcp" });
  });

  it("joins array values with commas", () => {
    expect(
      extractComplianceProviderFilters({
        "filter[provider_groups__in]": ["g1", "g2"],
      }),
    ).toEqual({ "filter[provider_groups__in]": "g1,g2" });
  });

  it("reads from URLSearchParams", () => {
    const params = new URLSearchParams();
    params.set("filter[provider_id__in]", "p1,p2");
    expect(extractComplianceProviderFilters(params)).toEqual({
      "filter[provider_id__in]": "p1,p2",
    });
  });

  it("returns an empty object when no provider filters are present", () => {
    expect(extractComplianceProviderFilters({ scanId: "scan-1" })).toEqual({});
  });
});
