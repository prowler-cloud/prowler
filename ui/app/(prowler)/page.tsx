import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./_new-overview/components/accounts-selector";
import { CheckFindingsSSR } from "./_new-overview/components/check-findings";
import { GraphsTabsWrapper } from "./_new-overview/components/graphs-tabs/graphs-tabs-wrapper";
import { RiskPipelineViewSkeleton } from "./_new-overview/components/graphs-tabs/risk-pipeline-view";
import { ProviderTypeSelector } from "./_new-overview/components/provider-type-selector";
import {
  RiskSeverityChartSkeleton,
  RiskSeverityChartSSR,
} from "./_new-overview/components/risk-severity-chart";
import { StatusChartSkeleton } from "./_new-overview/components/status-chart";
import {
  ThreatScoreSkeleton,
  ThreatScoreSSR,
} from "./_new-overview/components/threat-score";
import {
  ComplianceWatchlistSSR,
  ServiceWatchlistSSR,
  WatchlistCardSkeleton,
} from "./_new-overview/components/watchlist";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
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

      <div className="mt-6 flex flex-col gap-6 md:flex-row md:items-stretch">
        <div className="flex flex-col gap-6">
          <Suspense fallback={<WatchlistCardSkeleton />}>
            <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
          </Suspense>

          <Suspense fallback={<WatchlistCardSkeleton />}>
            <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
          </Suspense>
        </div>

        <Suspense fallback={<RiskPipelineViewSkeleton />}>
          <GraphsTabsWrapper searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}
