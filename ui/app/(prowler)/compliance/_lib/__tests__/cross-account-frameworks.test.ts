import { describe, expect, it } from "vitest";

import {
  buildCrossAccountDetailHref,
  parseCrossAccountFilters,
} from "../cross-account-frameworks";

describe("buildCrossAccountDetailHref", () => {
  it("builds the detail path with mode, identity and provider type", () => {
    const href = buildCrossAccountDetailHref({
      complianceId: "cis_2.0_aws",
      title: "CIS",
      version: "2.0",
      providerType: "aws",
    });

    const url = new URL(href, "https://example.test");
    expect(url.pathname).toBe("/compliance/CIS");
    expect(url.searchParams.get("mode")).toBe("cross-account");
    expect(url.searchParams.get("complianceId")).toBe("cis_2.0_aws");
    expect(url.searchParams.get("version")).toBe("2.0");
    expect(url.searchParams.get("providerType")).toBe("aws");
  });

  it("forwards only the cross-account filter params", () => {
    const href = buildCrossAccountDetailHref(
      {
        complianceId: "cis_2.0_aws",
        title: "CIS",
        version: "2.0",
        providerType: "aws",
      },
      {
        "filter[provider_id__in]": "acc-1,acc-2",
        "filter[provider_groups__in]": "group-1",
        // Not part of the cross-account contract: must not leak into the link.
        "filter[provider_type__in]": "aws,azure",
        unrelated: "x",
      },
    );

    const url = new URL(href, "https://example.test");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe("acc-1,acc-2");
    expect(url.searchParams.get("filter[provider_groups__in]")).toBe("group-1");
    expect(url.searchParams.has("filter[provider_type__in]")).toBe(false);
    expect(url.searchParams.has("unrelated")).toBe(false);
  });
});

describe("parseCrossAccountFilters", () => {
  it("extracts the endpoint filters and drops empties", () => {
    expect(
      parseCrossAccountFilters({
        "filter[provider_id__in]": "acc-1",
        "filter[provider_groups__in]": "",
      }),
    ).toEqual({ providerIds: "acc-1", providerGroups: undefined });

    expect(parseCrossAccountFilters({})).toEqual({
      providerIds: undefined,
      providerGroups: undefined,
    });
  });
});
