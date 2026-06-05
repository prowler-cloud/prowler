import { getAllProviders } from "@/actions/providers";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { SkeletonBoundary } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

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
  const providersData = await getAllProviders();

  return (
    <ContentLayout title="Overview" icon="lucide:square-chart-gantt">
      <div className="xxl:grid-cols-4 mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <ProviderAccountSelectors providers={providersData?.data ?? []} />
      </div>

      <div className="flex flex-col gap-6 xl:flex-row xl:flex-wrap xl:items-stretch">
        <SkeletonBoundary
          fallback={<ThreatScoreSkeleton />}
          className="w-full lg:max-w-[312px]"
        >
          <ThreatScoreSSR searchParams={resolvedSearchParams} />
        </SkeletonBoundary>

        <SkeletonBoundary
          fallback={<StatusChartSkeleton />}
          className="min-w-[312px] flex-1 md:min-w-[380px]"
        >
          <CheckFindingsSSR searchParams={resolvedSearchParams} />
        </SkeletonBoundary>

        <SkeletonBoundary
          fallback={<RiskSeverityChartSkeleton />}
          className="min-w-[312px] flex-1 md:min-w-[380px]"
        >
          <RiskSeverityChartSSR searchParams={resolvedSearchParams} />
        </SkeletonBoundary>
      </div>

      <div className="mt-6">
        <SkeletonBoundary fallback={<ResourcesInventorySkeleton />}>
          <ResourcesInventorySSR searchParams={resolvedSearchParams} />
        </SkeletonBoundary>
      </div>

      <div className="mt-6 flex flex-col gap-6 xl:flex-row">
        {/* Watchlists: stacked on mobile, row on tablet, stacked on desktop */}
        <div className="flex min-w-0 flex-col gap-6 overflow-hidden sm:flex-row sm:flex-wrap sm:items-stretch xl:w-[312px] xl:shrink-0 xl:flex-col">
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            <SkeletonBoundary fallback={<WatchlistCardSkeleton />}>
              <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
            </SkeletonBoundary>
          </div>
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            <SkeletonBoundary fallback={<WatchlistCardSkeleton />}>
              <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
            </SkeletonBoundary>
          </div>
        </div>

        {/* Charts column: Attack Surface on top, Findings Over Time below */}
        <div className="flex flex-1 flex-col gap-6">
          <SkeletonBoundary fallback={<AttackSurfaceSkeleton />}>
            <AttackSurfaceSSR searchParams={resolvedSearchParams} />
          </SkeletonBoundary>
          <SkeletonBoundary fallback={<FindingSeverityOverTimeSkeleton />}>
            <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
          </SkeletonBoundary>
        </div>
      </div>

      <div className="mt-6">
        <SkeletonBoundary fallback={<RiskPipelineViewSkeleton />}>
          <GraphsTabsWrapper searchParams={resolvedSearchParams} />
        </SkeletonBoundary>
      </div>
    </ContentLayout>
  );
}
