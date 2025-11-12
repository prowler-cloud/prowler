import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./components/accounts-selector";
import { CheckFindingsSSR } from "./components/check-findings";
import {
  FindingSeverityOverTimeSkeleton,
  FindingSeverityOverTimeSSR,
} from "./components/finding-severity-over-time/finding-severity-over-time.ssr";
import { GraphsTabsWrapper } from "./components/graphs-tabs/graphs-tabs-wrapper";
import { ProviderTypeSelector } from "./components/provider-type-selector";
import { RiskSeverityChartSkeleton } from "./components/risk-severity-chart";
import { RiskSeverityChartSSR } from "./components/risk-severity-chart/risk-severity-chart.ssr";
import { StatusChartSkeleton } from "./components/status-chart";
import { ThreatScoreSkeleton, ThreatScoreSSR } from "./components/threat-score";
import { ServiceWatchlist } from "./components/watchlist";
import { ComplianceWatchlist } from "./components/watchlist/compliance-watchlist";

export default async function NewOverviewPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
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
        <ComplianceWatchlist />
        <Suspense fallback={<FindingSeverityOverTimeSkeleton />}>
          <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
      <div className="mt-6 flex gap-6">
        <ServiceWatchlist />
        <GraphsTabsWrapper searchParams={resolvedSearchParams} />
      </div>
    </ContentLayout>
  );
}
