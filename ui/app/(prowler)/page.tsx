import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import { getLatestFindings } from "@/actions/findings/findings";
import {
  getFindingsBySeverity,
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import { FilterControls } from "@/components/filters";
import { LighthouseBanner } from "@/components/lighthouse";
import {
  FindingsBySeverityChart,
  FindingsByStatusChart,
  LinkToFindings,
  ProvidersOverview,
  SkeletonFindingsBySeverityChart,
  SkeletonFindingsByStatusChart,
  SkeletonProvidersOverview,
} from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { SkeletonTableNewFindings } from "@/components/overview/new-findings-table/table/skeleton-table-new-findings";
import { ContentLayout } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib/helper";
import { FindingProps, SearchParamsProps } from "@/types";

const FILTER_PREFIX = "filter[";

// Extract only query params that start with "filter[" for API calls
function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});
  return (
    <ContentLayout title="Overview" icon="lucide:square-chart-gantt">
      <FilterControls providers mutedFindings showClearButton={false} />

      <div className="grid grid-cols-12 gap-12 lg:gap-6">
        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonProvidersOverview />}>
            <SSRProvidersOverview />
          </Suspense>
        </div>

        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonFindingsBySeverityChart />}>
            <SSRFindingsBySeverity searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <div className="col-span-12 lg:col-span-4">
          <Suspense fallback={<SkeletonFindingsByStatusChart />}>
            <SSRFindingsByStatus searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <div className="col-span-12">
          <Spacer y={16} />
          <Suspense
            key={searchParamsKey}
            fallback={<SkeletonTableNewFindings />}
          >
            <SSRDataNewFindingsTable searchParams={resolvedSearchParams} />
          </Suspense>
        </div>
      </div>
    </ContentLayout>
  );
}

const SSRProvidersOverview = async () => {
  const providersOverview = await getProvidersOverview({});

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">Providers Overview</h3>
      <ProvidersOverview providersOverview={providersOverview} />
    </>
  );
};

const SSRFindingsByStatus = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">Findings by Status</h3>
      <FindingsByStatusChart findingsByStatus={findingsByStatus} />
    </>
  );
};

const SSRFindingsBySeverity = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const defaultFilters = {
    "filter[status]": "FAIL",
  } as const;

  const filters = pickFilterParams(searchParams);

  const combinedFilters = { ...defaultFilters, ...filters };

  const findingsBySeverity = await getFindingsBySeverity({
    filters: combinedFilters,
  });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">
        Failed Findings by Severity
      </h3>
      <FindingsBySeverityChart findingsBySeverity={findingsBySeverity} />
    </>
  );
};

const SSRDataNewFindingsTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const page = 1;
  const sort = "severity,-inserted_at";

  const defaultFilters = {
    "filter[status]": "FAIL",
    "filter[delta]": "new",
  };

  const filters = pickFilterParams(searchParams);

  const combinedFilters = { ...defaultFilters, ...filters };

  const findingsData = await getLatestFindings({
    query: undefined,
    page,
    sort,
    filters: combinedFilters,
  });

  // Create dictionaries for resources, scans, and providers
  const resourceDict = createDict("resources", findingsData);
  const scanDict = createDict("scans", findingsData);
  const providerDict = createDict("providers", findingsData);

  // Expand each finding with its corresponding resource, scan, and provider
  const expandedFindings = findingsData?.data
    ? findingsData.data.map((finding: FindingProps) => {
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

        return {
          ...finding,
          relationships: { scan, resource, provider },
        };
      })
    : [];

  // Create the new object while maintaining the original structure
  const expandedResponse = {
    ...findingsData,
    data: expandedFindings,
  };

  return (
    <>
      <div className="relative flex w-full">
        <div className="flex w-full items-center gap-2">
          <h3 className="text-sm font-bold uppercase">
            Latest new failing findings
          </h3>
          <p className="text-xs text-gray-500">
            Showing the latest 10 new failing findings by severity.
          </p>
        </div>
        <div className="absolute -top-6 right-0">
          <LinkToFindings />
        </div>
      </div>
      <Spacer y={4} />

      <LighthouseBanner />

      <DataTable
        key={`dashboard-${Date.now()}`}
        columns={ColumnNewFindingsToDate}
        data={expandedResponse?.data || []}
        // metadata={findingsData?.meta}
      />
    </>
  );
};
