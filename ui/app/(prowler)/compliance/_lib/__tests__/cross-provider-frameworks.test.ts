import { describe, expect, it } from "vitest";

import type { CrossProviderFrameworkEntry } from "../cross-provider-frameworks";
import { buildCrossProviderDetailHref } from "../cross-provider-frameworks";

const entry: CrossProviderFrameworkEntry = {
  complianceId: "csa_ccm_4.0",
  title: "CSA-CCM",
  version: "4.0",
  description: "CSA Cloud Controls Matrix v4.0.",
  providerTypes: ["aws", "azure"],
};

describe("buildCrossProviderDetailHref", () => {
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
    expect(url.searchParams.has("filter[region__in]")).toBe(false);
    expect(url.searchParams.has("filter[cis_profile_level]")).toBe(false);
    expect(url.searchParams.has("scanId")).toBe(false);
    expect(url.searchParams.has("tab")).toBe(false);
  });
});
