import { Suspense } from "react";

import {
  adaptFindingGroupsResponse,
  getFindingGroups,
  getLatestFindingGroups,
} from "@/actions/finding-groups";
import { getLatestMetadataInfo, getMetadataInfo } from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScan, getScans } from "@/actions/scans";
import { FindingsFilters } from "@/components/findings/findings-filters";
import {
  FindingsGroupTable,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
import {
  applyDefaultMutedFilter,
  createScanDetailsMapping,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
import { resolveFindingScanDateFilters } from "@/lib/findings-scan-filters";
import { ScanEntity, ScanProps } from "@/types";
import { SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const { encodedSort } = extractSortAndKey(resolvedSearchParams);
  const { filters, query } = extractFiltersAndQuery(resolvedSearchParams);

  const [providersData, scansData] = await Promise.all([
    getProviders({ pageSize: 50 }),
    getScans({ pageSize: 50 }),
  ]);

  const filtersWithScanDates = applyDefaultMutedFilter(
    await resolveFindingScanDateFilters({
      filters,
      scans: scansData?.data || [],
      loadScan: async (scanId: string) => {
        const response = await getScan(scanId);
        return response?.data;
      },
    }),
  );

  const hasHistoricalData = hasDateOrScanFilter(filtersWithScanDates);

  const metadataInfoData = await (
    hasHistoricalData ? getMetadataInfo : getLatestMetadataInfo
  )({
    query,
    sort: encodedSort,
    filters: filtersWithScanDates,
  });

  // Extract unique regions, services, categories, groups from the new endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];
  const uniqueCategories = metadataInfoData?.data?.attributes?.categories || [];
  const uniqueGroups = metadataInfoData?.data?.attributes?.groups || [];

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data?.filter(
    (scan: ScanProps) =>
      scan.attributes.state === "completed" &&
      scan.attributes.unique_resource_count > 1,
  );

  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];

  const scanDetails = createScanDetailsMapping(
    completedScans || [],
    providersData,
  ) as { [uid: string]: ScanEntity }[];

  return (
    <ContentLayout title="Findings" icon="lucide:tag">
      <FilterTransitionWrapper>
        <div className="mb-6">
          <FindingsFilters
            providers={providersData?.data || []}
            completedScanIds={completedScanIds}
            scanDetails={scanDetails}
            uniqueRegions={uniqueRegions}
            uniqueServices={uniqueServices}
            uniqueResourceTypes={uniqueResourceTypes}
            uniqueCategories={uniqueCategories}
            uniqueGroups={uniqueGroups}
          />
        </div>
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable
            searchParams={resolvedSearchParams}
            filters={filtersWithScanDates}
          />
        </Suspense>
      </FilterTransitionWrapper>
    </ContentLayout>
  );
}

const SSRDataTable = async ({
  searchParams,
  filters,
}: {
  searchParams: SearchParamsProps;
  filters: Record<string, string>;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);

  const { encodedSort } = extractSortAndKey(searchParams);
  const hasHistoricalData = hasDateOrScanFilter(filters);

  const fetchFindingGroups = hasHistoricalData
    ? getFindingGroups
    : getLatestFindingGroups;

  const findingGroupsData = await fetchFindingGroups({
    page,
    ...(encodedSort && { sort: encodedSort }),
    filters,
    pageSize,
  });

  // Transform API response to FindingGroupRow[]
  const groups = adaptFindingGroupsResponse(findingGroupsData);
  // Key resets all client state (selection, drill-down) when data changes
  const groupKey = groups.map((g) => g.id).join(",");

  return (
    <>
      {findingGroupsData?.errors?.length > 0 && (
        <div className="text-small mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{findingGroupsData.errors[0].detail}</p>
        </div>
      )}
      <FindingsGroupTable
        key={groupKey}
        data={groups}
        metadata={findingGroupsData?.meta}
        resolvedFilters={filters}
        hasHistoricalData={hasHistoricalData}
      />
    </>
  );
};
