import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];

// Each fetch records when it starts and resolves on the next tick, so the
// order proves whether the section awaits them one by one or all at once.
const gate = (name: string, value: unknown) =>
  vi.fn(() => {
    calls.push(`start:${name}`);
    return new Promise((resolve) => {
      setTimeout(() => {
        calls.push(`end:${name}`);
        resolve(value);
      }, 0);
    });
  });

const mocks = vi.hoisted(() => ({
  getFindingGroups: vi.fn(),
  getLatestFindingGroups: vi.fn(),
  getSelectedFindingCheckOptions: vi.fn(),
  getAllProviders: vi.fn(),
  getAllProviderGroups: vi.fn(),
  getLatestMetadataInfo: vi.fn(),
  getMetadataInfo: vi.fn(),
}));

vi.mock("@/actions/finding-groups", () => ({
  getFindingGroups: mocks.getFindingGroups,
  getLatestFindingGroups: mocks.getLatestFindingGroups,
}));
vi.mock("@/lib/finding-group-filter-options", () => ({
  getSelectedFindingCheckOptions: mocks.getSelectedFindingCheckOptions,
}));
vi.mock("@/actions/providers", () => ({
  getAllProviders: mocks.getAllProviders,
}));
vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: mocks.getAllProviderGroups,
}));
vi.mock("@/actions/findings", () => ({
  getLatestMetadataInfo: mocks.getLatestMetadataInfo,
  getMetadataInfo: mocks.getMetadataInfo,
}));
vi.mock("@/app/(prowler)/alerts/_components", () => ({
  SeedFromFindingsButton: () => null,
}));
vi.mock("@/components/findings/findings-filters", () => ({
  FindingsFilters: () => null,
}));
vi.mock("@/lib", () => ({
  createScanDetailsMapping: (scans: Array<{ id: string }>) =>
    scans.map((scan) => ({ [scan.id]: { id: scan.id } })),
  splitCsvFilterValues: (value?: string) =>
    value ? value.split(",").filter(Boolean) : [],
}));
vi.mock("@/lib/shared/env", () => ({
  isCloud: () => false,
}));

import type { ScanProps } from "@/types";

import { FindingsFiltersSection } from "./findings-filters-section";

const providers = { data: [{ id: "provider-1" }] };
const providerGroups = { data: [{ id: "group-1" }] };
const metadata = {
  data: {
    attributes: {
      regions: ["eu-west-1"],
      services: ["s3"],
      resource_types: ["bucket"],
      categories: ["storage"],
      groups: ["prod"],
    },
  },
};

const baseProps = {
  filters: { "filter[severity__in]": "high" },
  resolvedFilters: { "filter[severity__in]": "high", "filter[muted]": "false" },
  hasHistoricalData: false,
  query: "",
  completedScans: [{ id: "scan-1" }] as unknown as ScanProps[],
};

describe("FindingsFiltersSection", () => {
  beforeEach(() => {
    calls.length = 0;
    vi.clearAllMocks();
    mocks.getAllProviders.mockImplementation(gate("providers", providers));
    mocks.getAllProviderGroups.mockImplementation(
      gate("groups", providerGroups),
    );
    mocks.getLatestMetadataInfo.mockImplementation(gate("metadata", metadata));
    mocks.getMetadataInfo.mockImplementation(gate("metadata", metadata));
    mocks.getSelectedFindingCheckOptions.mockImplementation(
      gate("selected", []),
    );
  });

  it("starts every filter source before any of them resolves", async () => {
    // When
    await FindingsFiltersSection(baseProps);

    // Then
    expect(calls.slice(0, 4)).toEqual([
      "start:providers",
      "start:groups",
      "start:metadata",
      "start:selected",
    ]);
  });

  it("uses the latest metadata and hands the check options over to the client", async () => {
    // When
    const element = (await FindingsFiltersSection(baseProps)) as ReactElement<
      Record<string, unknown>
    >;

    // Then
    expect(mocks.getLatestMetadataInfo).toHaveBeenCalledWith({
      query: "",
      sort: undefined,
      filters: baseProps.resolvedFilters,
    });
    expect(mocks.getMetadataInfo).not.toHaveBeenCalled();
    expect(element.props).toMatchObject({
      providers: providers.data,
      providerGroups: providerGroups.data,
      completedScanIds: ["scan-1"],
      uniqueRegions: ["eu-west-1"],
      uniqueServices: ["s3"],
      checkOptionsSource: {
        filters: baseProps.resolvedFilters,
        hasHistoricalData: false,
        initialOptions: [],
      },
    });
    expect(mocks.getSelectedFindingCheckOptions).toHaveBeenCalledWith({
      fetchFindingGroups: mocks.getLatestFindingGroups,
      filters: baseProps.resolvedFilters,
      selectedCheckIds: [],
    });
  });

  it("resolves the titles of the checks selected in the URL", async () => {
    // Given
    const selected = [{ checkId: "check-a", checkTitle: "Check A" }];
    mocks.getSelectedFindingCheckOptions.mockResolvedValue(selected);

    // When
    const element = (await FindingsFiltersSection({
      ...baseProps,
      resolvedFilters: {
        ...baseProps.resolvedFilters,
        "filter[check_id__in]": "check-a,check-b",
      },
    })) as ReactElement<Record<string, unknown>>;

    // Then
    expect(mocks.getSelectedFindingCheckOptions).toHaveBeenCalledWith(
      expect.objectContaining({ selectedCheckIds: ["check-a", "check-b"] }),
    );
    expect(element.props.checkOptionsSource).toMatchObject({
      initialOptions: selected,
    });
  });

  it("uses the historical endpoints when a date or scan filter is set", async () => {
    // When
    const element = (await FindingsFiltersSection({
      ...baseProps,
      hasHistoricalData: true,
    })) as ReactElement<Record<string, unknown>>;

    // Then
    expect(mocks.getMetadataInfo).toHaveBeenCalledTimes(1);
    expect(mocks.getLatestMetadataInfo).not.toHaveBeenCalled();
    expect(element.props.checkOptionsSource).toMatchObject({
      hasHistoricalData: true,
    });
    expect(mocks.getSelectedFindingCheckOptions).toHaveBeenCalledWith(
      expect.objectContaining({ fetchFindingGroups: mocks.getFindingGroups }),
    );
  });
});
