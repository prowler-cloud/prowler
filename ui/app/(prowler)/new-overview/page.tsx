import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./components/accounts-selector";
import { FindingSeverityOverTimeSSR } from "./components/finding-severity-over-time";
import { ProviderTypeSelector } from "./components/provider-type-selector";
import { RiskSeverityChartSSR } from "./components/risk-severity-chart";
import { StatusChartSSR } from "./components/status-chart";

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
      <div className="grid auto-rows-fr gap-6 md:grid-cols-2">
        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <StatusChartSSR searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <RiskSeverityChartSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
      <div className="mt-6">
        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}
