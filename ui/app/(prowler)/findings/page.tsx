import { Suspense } from "react";

import {
  adaptFindingGroupsResponse,
  getFindingGroups,
  getLatestFindingGroups,
} from "@/actions/finding-groups";
import { getScan, getScans } from "@/actions/scans";
import {
  FindingsGroupTable,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FilterTransitionWrapper } from "@/contexts";
import {
  applyDefaultMutedFilter,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
import { resolveFindingScanDateFilters } from "@/lib/findings-scan-filters";
import { ScanProps } from "@/types";
import { SearchParamsProps } from "@/types/components";

import { FindingsFiltersSection } from "./_components/findings-filters-section";
import { FindingsFiltersSkeleton } from "./_components/findings-filters-skeleton";

export default async function Findings({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const { encodedSort } = extractSortAndKey(resolvedSearchParams);
  const { filters, query } = extractFiltersAndQuery(resolvedSearchParams);

  const [scansData, filtersWithScanDates] = await Promise.all([
    getScans({
      pageSize: 50,
      filters: { "filter[state]": "completed" },
      fields: {
        scans: "name,state,unique_resource_count,completed_at,provider",
      },
    }),
    resolveFindingScanDateFilters({
      filters,
      scans: [],
      loadScan: async (scanId: string) => {
        const response = await getScan(scanId);
        return response?.data;
      },
    }),
  ]);
  const resolvedFilters = applyDefaultMutedFilter(filtersWithScanDates);
  const hasHistoricalData = hasDateOrScanFilter(filtersWithScanDates);

  const completedScans: ScanProps[] =
    scansData?.data?.filter(
      (scan: ScanProps) =>
        scan.attributes.state === "completed" &&
        scan.attributes.unique_resource_count > 1,
    ) || [];

  const onboardingAction =
    completedScans.length > 0
      ? { flowId: "explore-findings" }
      : {
          flowId: "explore-findings",
          fallbackFlowId: "view-first-scan",
          useFallback: true,
        };

  return (
    <ContentLayout
      title="Findings"
      icon="lucide:tag"
      onboardingAction={onboardingAction}
    >
      <FilterTransitionWrapper>
        <div className="mb-6">
          <Suspense fallback={<FindingsFiltersSkeleton />}>
            <FindingsFiltersSection
              filters={filters}
              resolvedFilters={resolvedFilters}
              hasHistoricalData={hasHistoricalData}
              query={query}
              encodedSort={encodedSort}
              completedScans={completedScans}
            />
          </Suspense>
        </div>
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable
            searchParams={resolvedSearchParams}
            filters={resolvedFilters}
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
  const expandedCheckIdParam = searchParams.expandedCheckId;
  const expandedCheckId = Array.isArray(expandedCheckIdParam)
    ? expandedCheckIdParam[0]
    : expandedCheckIdParam;

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

  const groups = adaptFindingGroupsResponse(findingGroupsData);
  // Key resets client state (selection, drill-down) when data changes.
  const groupKey = groups.map((g) => g.id).join(",");

  return (
    <>
      {findingGroupsData?.errors?.length > 0 && (
        <div className="mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-sm text-red-700">
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
        expandedCheckId={expandedCheckId}
      />
    </>
  );
};
