import {
  getFindingGroups,
  getLatestFindingGroups,
} from "@/actions/finding-groups";
import { getLatestMetadataInfo, getMetadataInfo } from "@/actions/findings";
import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { SeedFromFindingsButton } from "@/app/(prowler)/alerts/_components";
import { FindingsFilters } from "@/components/findings/findings-filters";
import { createScanDetailsMapping, splitCsvFilterValues } from "@/lib";
import { getSelectedFindingCheckOptions } from "@/lib/finding-group-filter-options";
import { isCloud } from "@/lib/shared/env";
import { ScanEntity, ScanProps } from "@/types";

interface FindingsFiltersSectionProps {
  filters: Record<string, string>;
  resolvedFilters: Record<string, string>;
  hasHistoricalData: boolean;
  query: string;
  encodedSort?: string;
  completedScans: ScanProps[];
}

export async function FindingsFiltersSection({
  filters,
  resolvedFilters,
  hasHistoricalData,
  query,
  encodedSort,
  completedScans,
}: FindingsFiltersSectionProps) {
  const fetchFindingGroups = hasHistoricalData
    ? getFindingGroups
    : getLatestFindingGroups;
  const selectedCheckIds = [
    ...splitCsvFilterValues(resolvedFilters["filter[check_id]"]),
    ...splitCsvFilterValues(resolvedFilters["filter[check_id__in]"]),
  ];

  const [providersData, providerGroupsData, metadataInfoData, selectedChecks] =
    await Promise.all([
      getAllProviders(),
      getAllProviderGroups(),
      (hasHistoricalData ? getMetadataInfo : getLatestMetadataInfo)({
        query,
        sort: encodedSort,
        filters: resolvedFilters,
      }),
      getSelectedFindingCheckOptions({
        fetchFindingGroups,
        filters: resolvedFilters,
        selectedCheckIds,
      }),
    ]);

  const attributes = metadataInfoData?.data?.attributes;
  const uniqueRegions = attributes?.regions || [];
  const uniqueServices = attributes?.services || [];
  const uniqueResourceTypes = attributes?.resource_types || [];
  const uniqueCategories = attributes?.categories || [];
  const uniqueGroups = attributes?.groups || [];

  const providers = providersData?.data || [];
  const completedScanIds = completedScans.map((scan) => scan.id);
  const scanDetails = createScanDetailsMapping(
    completedScans,
    providersData,
  ) as { [uid: string]: ScanEntity }[];

  return (
    <FindingsFilters
      providers={providers}
      providerGroups={providerGroupsData?.data || []}
      completedScanIds={completedScanIds}
      scanDetails={scanDetails}
      uniqueRegions={uniqueRegions}
      uniqueServices={uniqueServices}
      uniqueResourceTypes={uniqueResourceTypes}
      uniqueCategories={uniqueCategories}
      uniqueGroups={uniqueGroups}
      checkOptionsSource={{
        filters: resolvedFilters,
        hasHistoricalData,
        initialOptions: selectedChecks,
      }}
      trailingControls={
        <SeedFromFindingsButton
          filterBag={filters}
          providers={providers}
          scans={scanDetails}
          uniqueRegions={uniqueRegions}
          uniqueServices={uniqueServices}
          uniqueResourceTypes={uniqueResourceTypes}
          uniqueCategories={uniqueCategories}
          uniqueGroups={uniqueGroups}
          isCloudEnabled={isCloud()}
        />
      }
    />
  );
}
