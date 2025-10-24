import { Suspense } from "react";

import { getFindingsByStatus } from "@/actions/overview/overview";
import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./components/accounts-selector";
import { CheckFindings } from "./components/check-findings";
import { ProviderTypeSelector } from "./components/provider-type-selector";

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
      <div className="flex flex-col gap-6 md:flex-row">
        <Suspense
          fallback={
            <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <SSRCheckFindings searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

const SSRCheckFindings = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  if (!findingsByStatus) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const {
    fail = 0,
    pass = 0,
    muted_new = 0,
    muted_changed = 0,
    fail_new = 0,
    pass_new = 0,
  } = findingsByStatus?.data?.attributes || {};

  const mutedTotal = muted_new + muted_changed;

  return (
    <CheckFindings
      failFindingsData={{
        total: fail,
        new: fail_new,
        muted: mutedTotal,
      }}
      passFindingsData={{
        total: pass,
        new: pass_new,
        muted: mutedTotal,
      }}
    />
  );
};
