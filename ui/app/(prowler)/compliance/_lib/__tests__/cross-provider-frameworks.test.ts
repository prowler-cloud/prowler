import { describe, expect, it } from "vitest";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { PROVIDER_TYPES } from "@/types/providers";

import {
  buildCrossProviderDetailHref,
  CROSS_PROVIDER_FRAMEWORKS,
  resolveCrossProviderFramework,
} from "../cross-provider-frameworks";

describe("CROSS_PROVIDER_FRAMEWORKS catalog", () => {
  it("uses titles that resolve to a compliance icon", () => {
    for (const entry of CROSS_PROVIDER_FRAMEWORKS) {
      expect(getComplianceIcon(entry.title), entry.title).not.toBeNull();
    }
  });

  it("only lists providers the UI knows how to render", () => {
    for (const entry of CROSS_PROVIDER_FRAMEWORKS) {
      for (const provider of entry.compatibleProviders) {
        expect(PROVIDER_TYPES).toContain(provider);
      }
      expect(new Set(entry.compatibleProviders).size).toBe(
        entry.compatibleProviders.length,
      );
    }
  });
});

describe("resolveCrossProviderFramework", () => {
  it.each([
    [undefined, "CSA-CCM"],
    ["csa_ccm_4.0", "DORA"],
    ["csa_ccm_4.0", "csa-ccm"],
  ])("rejects invalid detail links", (complianceId, title) => {
    expect(resolveCrossProviderFramework(complianceId, title)).toBeUndefined();
  });

  it("resolves the catalog entry for a valid detail link", () => {
    // Given
    const expected = CROSS_PROVIDER_FRAMEWORKS[0];

    // When
    const framework = resolveCrossProviderFramework(
      expected.complianceId,
      expected.title,
    );

    // Then
    expect(framework).toEqual(expected);
  });
});

describe("buildCrossProviderDetailHref", () => {
  const entry = CROSS_PROVIDER_FRAMEWORKS[0];

  it("builds the detail path with cross-provider mode and identity params", () => {
    const href = buildCrossProviderDetailHref(entry);

    expect(href).toBe(
      `/compliance/${encodeURIComponent(entry.title)}?mode=cross-provider&complianceId=${encodeURIComponent(entry.complianceId)}&version=${encodeURIComponent(entry.version)}`,
    );
  });

  it("forwards only the cross-provider filter params present in searchParams", () => {
    const href = buildCrossProviderDetailHref(entry, {
      "filter[provider_type__in]": "aws,gcp",
      "filter[provider_id__in]": "prov-1",
      "filter[provider_groups__in]": "group-1",
      "filter[region__in]": "eu-west-1",
      "filter[cis_profile_level]": "Level 1",
      scanId: "scan-1",
      tab: "cross-provider",
    });

    const url = new URL(href, "https://localhost");
    expect(url.searchParams.get("mode")).toBe("cross-provider");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws,gcp");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe("prov-1");
    expect(url.searchParams.get("filter[provider_groups__in]")).toBe("group-1");
    expect(url.searchParams.get("filter[region__in]")).toBe("eu-west-1");
    expect(url.searchParams.has("filter[cis_profile_level]")).toBe(false);
    expect(url.searchParams.has("scanId")).toBe(false);
    expect(url.searchParams.has("tab")).toBe(false);
  });
});
