import { Spacer } from "@nextui-org/react";
import { format, subDays } from "date-fns";
import { Suspense } from "react";

import { getFindings } from "@/actions/findings/findings";
import {
  getFindingsBySeverity,
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import { FilterControls } from "@/components/filters";
import { LighthouseBannerWrapper } from "@/components/lighthouse/lighthouse-banner-wrapper";
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

export default function Home({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <ContentLayout title="Overview" icon="solar:pie-chart-2-outline">
      <Spacer y={4} />
      <FilterControls providers />
      <div className="mx-auto space-y-8 px-0 py-6">
        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-12 lg:col-span-4">
            <Suspense fallback={<SkeletonProvidersOverview />}>
              <SSRProvidersOverview />
            </Suspense>
          </div>

          <div className="col-span-12 lg:col-span-4">
            <Suspense fallback={<SkeletonFindingsBySeverityChart />}>
              <SSRFindingsBySeverity searchParams={searchParams} />
            </Suspense>
          </div>

          <div className="col-span-12 lg:col-span-4">
            <Suspense fallback={<SkeletonFindingsByStatusChart />}>
              <SSRFindingsByStatus searchParams={searchParams} />
            </Suspense>
          </div>

          <div className="col-span-12">
            <Spacer y={16} />
            <Suspense
              key={searchParamsKey}
              fallback={<SkeletonTableNewFindings />}
            >
              <SSRDataNewFindingsTable />
            </Suspense>
          </div>
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
  const filters = searchParams
    ? Object.fromEntries(
        Object.entries(searchParams).filter(([key]) =>
          key.startsWith("filter["),
        ),
      )
    : {};

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
  const filters = searchParams
    ? Object.fromEntries(
        Object.entries(searchParams).filter(([key]) =>
          key.startsWith("filter["),
        ),
      )
    : {};

  const findingsBySeverity = await getFindingsBySeverity({ filters });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold uppercase">Findings by Severity</h3>
      <FindingsBySeverityChart findingsBySeverity={findingsBySeverity} />
    </>
  );
};

const SSRDataNewFindingsTable = async () => {
  const page = 1;
  const sort = "severity,-inserted_at";

  const twoDaysAgo = format(subDays(new Date(), 2), "yyyy-MM-dd");

  const defaultFilters = {
    "filter[status__in]": "FAIL",
    "filter[delta__in]": "new",
    "filter[inserted_at__gte]": twoDaysAgo,
  };

  const findingsData = await getFindings({
    query: undefined,
    page,
    sort,
    filters: defaultFilters,
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
            Showing the latest 10 new failing findings by severity from the last
            2 days.
          </p>
        </div>
        <div className="absolute -top-6 right-0">
          <LinkToFindings />
        </div>
      </div>
      <Spacer y={4} />

      {/* Dynamic Lighthouse Banner */}
      <Suspense
        fallback={
          <div className="mb-6">
            <div className="mb-2 text-xs font-medium text-slate-500">
              AI-Powered Security Analysis
            </div>
            <div className="relative overflow-hidden rounded-xl border border-slate-600 bg-gradient-to-br from-slate-800 to-slate-900">
              {/* Left gradient accent bar */}
              <div className="absolute bottom-0 left-0 top-0 w-1 bg-gradient-to-b from-purple-500 to-violet-600"></div>

              <div className="flex items-center gap-4 p-5 pl-6">
                {/* Bot icon skeleton */}
                <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-purple-500 to-violet-600">
                  <div className="h-6 w-6 animate-pulse rounded bg-purple-300"></div>
                </div>

                {/* Content skeleton */}
                <div className="flex-1">
                  <div className="h-6 w-3/4 animate-pulse rounded bg-slate-600"></div>
                </div>
              </div>
            </div>
          </div>
        }
      >
        <LighthouseBannerWrapper />
      </Suspense>

      <Spacer y={4} />
      <DataTable
        columns={ColumnNewFindingsToDate}
        data={expandedResponse?.data || []}
        // metadata={findingsData?.meta}
      />
    </>
  );
};
