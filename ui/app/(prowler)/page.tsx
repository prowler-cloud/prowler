import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import { getLatestFindings } from "@/actions/findings/findings";
import { getProviders } from "@/actions/providers";
import { LighthouseBanner } from "@/components/lighthouse";
import { LinkToFindings } from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { SkeletonTableNewFindings } from "@/components/overview/new-findings-table/table/skeleton-table-new-findings";
import { ContentLayout } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib/helper";
import { FindingProps, SearchParamsProps } from "@/types";

import { AccountsSelector } from "./new-overview/components/accounts-selector";
import { CheckFindingsSSR } from "./new-overview/components/check-findings";
import { ProviderTypeSelector } from "./new-overview/components/provider-type-selector";
import {
  RiskSeverityChartSkeleton,
  RiskSeverityChartSSR,
} from "./new-overview/components/risk-severity-chart";
import { StatusChartSkeleton } from "./new-overview/components/status-chart";
import {
  ThreatScoreSkeleton,
  ThreatScoreSSR,
} from "./new-overview/components/threat-score";

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
  const providersData = await getProviders({ page: 1, pageSize: 200 });

  return (
    <ContentLayout title="Overview" icon="lucide:square-chart-gantt">
      <div className="xxl:grid-cols-4 mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <ProviderTypeSelector providers={providersData?.data ?? []} />
        <AccountsSelector providers={providersData?.data ?? []} />
      </div>

      <div className="flex flex-col gap-6 md:flex-row md:flex-wrap md:items-stretch">
        <Suspense fallback={<ThreatScoreSkeleton />}>
          <ThreatScoreSSR searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense fallback={<StatusChartSkeleton />}>
          <CheckFindingsSSR searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense fallback={<RiskSeverityChartSkeleton />}>
          <RiskSeverityChartSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>

      <div className="mt-6">
        <Spacer y={16} />
        <Suspense key={searchParamsKey} fallback={<SkeletonTableNewFindings />}>
          <SSRDataNewFindingsTable searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

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
