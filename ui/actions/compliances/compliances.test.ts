import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import {
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
  getCompliancesOverview,
} from "./compliances";

const calledUrl = () => new URL(fetchMock.mock.calls[0][0] as string);

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  handleApiResponseMock.mockResolvedValue({ data: [] });
});

describe("getCompliancesOverview", () => {
  it("sends scan_id and region in scan mode", async () => {
    await getCompliancesOverview({ scanId: "scan-1", region: "eu-west-1" });

    const url = calledUrl();
    expect(url.searchParams.get("filter[scan_id]")).toBe("scan-1");
    expect(url.searchParams.get("filter[region__in]")).toBe("eu-west-1");
  });

  it("forwards provider filters and omits scan_id in aggregated mode", async () => {
    await getCompliancesOverview({
      scanId: "scan-1",
      filters: { "filter[provider_type__in]": "aws,gcp" },
    });

    const url = calledUrl();
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws,gcp");
    // XOR: provider filters present -> never send scan_id (avoids backend 400)
    expect(url.searchParams.get("filter[scan_id]")).toBeNull();
  });
});

describe("getComplianceOverviewMetadataInfo", () => {
  it("forwards provider filters", async () => {
    await getComplianceOverviewMetadataInfo({
      filters: { "filter[provider_groups__in]": "g1,g2" },
    });

    expect(calledUrl().searchParams.get("filter[provider_groups__in]")).toBe(
      "g1,g2",
    );
  });
});

describe("getComplianceRequirements", () => {
  it("appends compliance_id and scan_id in scan mode", async () => {
    await getComplianceRequirements({
      complianceId: "cis_2.0_aws",
      scanId: "scan-1",
    });

    const url = calledUrl();
    expect(url.searchParams.get("filter[compliance_id]")).toBe("cis_2.0_aws");
    expect(url.searchParams.get("filter[scan_id]")).toBe("scan-1");
  });

  it("forwards provider filters and omits scan_id in aggregated mode", async () => {
    await getComplianceRequirements({
      complianceId: "cis_2.0_aws",
      scanId: "scan-1",
      filters: { "filter[provider_id__in]": "p1,p2" },
    });

    const url = calledUrl();
    expect(url.searchParams.get("filter[compliance_id]")).toBe("cis_2.0_aws");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe("p1,p2");
    expect(url.searchParams.get("filter[scan_id]")).toBeNull();
  });

  it("omits scan_id when no scan is provided", async () => {
    await getComplianceRequirements({ complianceId: "cis_2.0_aws" });

    expect(calledUrl().searchParams.get("filter[scan_id]")).toBeNull();
  });
});
