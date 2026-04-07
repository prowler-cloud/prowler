import { Suspense } from "react";

import {
  adaptFindingGroupsResponse,
  getFindingGroups,
  getLatestFindingGroups,
} from "@/actions/finding-groups";
import { getLatestMetadataInfo, getMetadataInfo } from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { FindingsFilters } from "@/components/findings/findings-filters";
import {
  FindingsGroupTable,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
import {
  createScanDetailsMapping,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
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

  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(resolvedSearchParams);

  // TODO: Re-implement deep link support (/findings?id=<uuid>) using the grouped view's resource detail drawer
  // once the legacy FindingDetailsSheet is fully deprecated (still used by /resources and overview dashboard).

  const [metadataInfoData, providersData, scansData] = await Promise.all([
    (hasDateOrScan ? getMetadataInfo : getLatestMetadataInfo)({
      query,
      sort: encodedSort,
      filters,
    }),
    getProviders({ pageSize: 50 }),
    getScans({ pageSize: 50 }),
  ]);

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
          <SSRDataTable searchParams={resolvedSearchParams} />
        </Suspense>
      </FilterTransitionWrapper>
    </ContentLayout>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const defaultSort = "-fail_count,-severity,-last_seen_at";

  const { encodedSort } = extractSortAndKey({
    ...searchParams,
    sort: searchParams.sort ?? defaultSort,
  });

  const { filters } = extractFiltersAndQuery(searchParams);
  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const fetchFindingGroups = hasDateOrScan
    ? getFindingGroups
    : getLatestFindingGroups;

  const findingGroupsData = await fetchFindingGroups({
    page,
    sort: encodedSort,
    filters,
    pageSize,
  });

  // Transform API response to FindingGroupRow[]
  const groups = adaptFindingGroupsResponse(findingGroupsData);
  // Key resets all client state (selection, drill-down) when data changes
  const groupKey = groups.map((g) => g.id).join(",");

  return (
    <>
      {findingGroupsData?.errors && (
        <div className="text-small mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{findingGroupsData.errors[0].detail}</p>
        </div>
      )}
      <FindingsGroupTable
        key={groupKey}
        data={groups}
        metadata={findingGroupsData?.meta}
      />
    </>
  );
};
