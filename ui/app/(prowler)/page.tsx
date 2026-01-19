import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "./_overview/_components/provider-type-selector";
import {
  AttackSurfaceSkeleton,
  AttackSurfaceSSR,
} from "./_overview/attack-surface";
import { CheckFindingsSSR } from "./_overview/check-findings";
import { GraphsTabsWrapper } from "./_overview/graphs-tabs/graphs-tabs-wrapper";
import { RiskPipelineViewSkeleton } from "./_overview/graphs-tabs/risk-pipeline-view";
import {
  ResourcesInventorySkeleton,
  ResourcesInventorySSR,
} from "./_overview/resources-inventory";
import {
  RiskSeverityChartSkeleton,
  RiskSeverityChartSSR,
} from "./_overview/risk-severity";
import {
  FindingSeverityOverTimeSkeleton,
  FindingSeverityOverTimeSSR,
} from "./_overview/severity-over-time/finding-severity-over-time.ssr";
import { StatusChartSkeleton } from "./_overview/status-chart";
import { ThreatScoreSkeleton, ThreatScoreSSR } from "./_overview/threat-score";
import {
  ComplianceWatchlistSSR,
  ServiceWatchlistSSR,
  WatchlistCardSkeleton,
} from "./_overview/watchlist";

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

      <div className="flex flex-col gap-6 xl:flex-row xl:flex-wrap xl:items-stretch">
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
        <Suspense fallback={<ResourcesInventorySkeleton />}>
          <ResourcesInventorySSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>

      <div className="mt-6 flex flex-col gap-6 xl:flex-row">
        {/* Watchlists: stacked on mobile, row on tablet, stacked on desktop */}
        <div className="flex min-w-0 flex-col gap-6 overflow-hidden sm:flex-row sm:flex-wrap sm:items-stretch xl:w-[312px] xl:shrink-0 xl:flex-col">
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            <Suspense fallback={<WatchlistCardSkeleton />}>
              <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
            </Suspense>
          </div>
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            <Suspense fallback={<WatchlistCardSkeleton />}>
              <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
            </Suspense>
          </div>
        </div>

        {/* Charts column: Attack Surface on top, Findings Over Time below */}
        <div className="flex flex-1 flex-col gap-6">
          <Suspense fallback={<AttackSurfaceSkeleton />}>
            <AttackSurfaceSSR searchParams={resolvedSearchParams} />
          </Suspense>
          <Suspense fallback={<FindingSeverityOverTimeSkeleton />}>
            <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
          </Suspense>
        </div>
      </div>

      <div className="mt-6">
        <Suspense fallback={<RiskPipelineViewSkeleton />}>
          <GraphsTabsWrapper searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}
