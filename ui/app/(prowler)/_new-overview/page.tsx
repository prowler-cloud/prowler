import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./_components/accounts-selector";
import { ProviderTypeSelector } from "./_components/provider-type-selector";
import { CheckFindingsSSR } from "./check-findings";
import { GraphsTabsWrapper } from "./graphs-tabs/graphs-tabs-wrapper";
import { RiskSeverityChartSkeleton } from "./risk-severity";
import { RiskSeverityChartSSR } from "./risk-severity/risk-severity-chart.ssr";
import {
  FindingSeverityOverTimeSkeleton,
  FindingSeverityOverTimeSSR,
} from "./severity-over-time/finding-severity-over-time.ssr";
import { StatusChartSkeleton } from "./status-chart";
import { ThreatScoreSkeleton, ThreatScoreSSR } from "./threat-score";
import {
  ComplianceWatchlistSSR,
  ServiceWatchlistSSR,
  WatchlistCardSkeleton,
} from "./watchlist";

export default async function NewOverviewPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  //if cloud env throw a 500 err
  if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
    throw new Error("500");
  }

  const resolvedSearchParams = await searchParams;
  const providersData = await getProviders({ page: 1, pageSize: 200 });

  return (
    <ContentLayout title="New Overview" icon="lucide:square-chart-gantt">
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
      <div className="mt-6 flex gap-6">
        <Suspense fallback={<WatchlistCardSkeleton />}>
          <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
        </Suspense>
        <Suspense fallback={<FindingSeverityOverTimeSkeleton />}>
          <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
      <div className="mt-6 flex gap-6">
        <Suspense fallback={<WatchlistCardSkeleton />}>
          <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
        </Suspense>
        <GraphsTabsWrapper searchParams={resolvedSearchParams} />
      </div>
    </ContentLayout>
  );
}
