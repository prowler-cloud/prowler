import { describe, expect, it, vi } from "vitest";

vi.mock("@/auth.config", () => ({ auth: vi.fn() }));

import { getResourceDrawerData } from "@/actions/resources";

import { SAMPLE_RESOURCE_GROUPS_RESPONSE } from "./sample-overview";
import { SAMPLE_FINDINGS, SAMPLE_RESOURCES } from "./sample-records";
import {
  filterSampleResources,
  getSampleResourceRow,
  SAMPLE_RESOURCE_FILTER_OPTIONS,
} from "./sample-resources";

describe("sample resources", () => {
  it("lists every sample resource with its failed findings count", () => {
    // When
    const { data, metadata } = filterSampleResources({ pageSize: "500" });

    // Then
    expect(metadata.pagination.count).toBe(SAMPLE_RESOURCES.length);
    expect(
      data.reduce(
        (total, row) => total + row.attributes.failed_findings_count,
        0,
      ),
    ).toBe(
      SAMPLE_FINDINGS.filter((finding) => finding.status === "FAIL").length,
    );
  });

  it("agrees with the Overview resource group counts", () => {
    for (const group of SAMPLE_RESOURCE_GROUPS_RESPONSE.data) {
      const { metadata } = filterSampleResources({
        "filter[groups__in]": group.id,
      });
      expect(metadata.pagination.count).toBe(group.attributes.resources_count);
    }
  });

  it("applies the filter bar, search, sort and paging", () => {
    // Given
    const [region] = SAMPLE_RESOURCE_FILTER_OPTIONS.regions;
    const inRegion = SAMPLE_RESOURCES.filter(
      (resource) => resource.region === region,
    );

    // When
    const filtered = filterSampleResources({
      "filter[region__in]": region,
      sort: "-type",
      pageSize: "500",
    });
    const searched = filterSampleResources({
      "filter[search]": SAMPLE_RESOURCES[0].name.toUpperCase(),
    });
    const secondPage = filterSampleResources({ page: "2", pageSize: "5" });

    // Then
    expect(filtered.data).toHaveLength(inRegion.length);
    const types = filtered.data.map((row) => row.attributes.type);
    expect(types).toEqual([...types].sort().reverse());
    expect(searched.data.map((row) => row.attributes.name)).toContain(
      SAMPLE_RESOURCES[0].name,
    );
    expect(secondPage.data).toHaveLength(5);
    expect(secondPage.metadata.pagination.page).toBe(2);
  });

  it("opens a sample resource drawer from its records, without the API", async () => {
    // Given
    const failing = SAMPLE_FINDINGS.find(
      (finding) => finding.status === "FAIL",
    )!;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    // When
    const drawer = await getResourceDrawerData({
      resourceId: failing.resource.id,
      resourceUid: failing.resource.uid,
      providerId: "sample-provider",
      providerType: "aws",
    });

    // Then
    expect(
      drawer.findings.map((finding: { id: string }) => finding.id),
    ).toContain(failing.id);
    expect(drawer.providerOrg).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("falls back to the default page size for invalid values", () => {
    for (const pageSize of ["-1", "0", "2.5", "abc"]) {
      const { data } = filterSampleResources({ pageSize });
      expect(data).toHaveLength(10);
    }
  });

  it("reopens a copied sample resource link", () => {
    const [resource] = SAMPLE_RESOURCES;

    expect(getSampleResourceRow(resource.id)?.attributes.name).toBe(
      resource.name,
    );
    expect(getSampleResourceRow("not-a-sample")).toBeNull();
  });

  it("searches the sample resource drawer's findings", async () => {
    // Given
    const failing = SAMPLE_FINDINGS.find(
      (finding) => finding.status === "FAIL",
    )!;
    const request = {
      resourceId: failing.resource.id,
      resourceUid: failing.resource.uid,
      providerId: "sample-provider",
      providerType: "aws",
    };

    // When
    const matching = await getResourceDrawerData({
      ...request,
      query: failing.check.title.toUpperCase(),
    });
    const none = await getResourceDrawerData({ ...request, query: "zzz" });

    // Then
    expect(
      matching.findings.map((finding: { id: string }) => finding.id),
    ).toContain(failing.id);
    expect(none.findings).toHaveLength(0);
  });
});
