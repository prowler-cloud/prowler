import { Suspense } from "react";

import { ProvidersAccountsView } from "@/components/providers";
import { SkeletonTableProviders } from "@/components/providers/table";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
import { SearchParamsProps } from "@/types";

import { AccountGroupsContent } from "./account-groups-content";
import { ProviderPageTabs } from "./provider-page-tabs";
import { getProviderTab } from "./provider-page-tabs.shared";
import { loadProvidersAccountsViewData } from "./providers-page.utils";

export default async function Providers({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const activeTab = getProviderTab(resolvedSearchParams.tab);

  // Exclude `tab` from the Suspense key so switching tabs doesn't re-suspend
  const { tab: _, ...paramsWithoutTab } = resolvedSearchParams || {};
  const searchParamsKey = JSON.stringify(paramsWithoutTab);

  return (
    <ContentLayout title="Cloud Providers" icon="lucide:cloud-cog">
      <FilterTransitionWrapper>
        <ProviderPageTabs
          activeTab={activeTab}
          accountsContent={
            <Suspense
              key={`accounts-${searchParamsKey}`}
              fallback={<ProvidersTableFallback />}
            >
              <ProvidersAccountsContent searchParams={resolvedSearchParams} />
            </Suspense>
          }
          accountGroupsContent={
            <Suspense
              key={`groups-${searchParamsKey}`}
              fallback={<AccountGroupsFallback />}
            >
              <AccountGroupsContent searchParams={resolvedSearchParams} />
            </Suspense>
          }
        />
      </FilterTransitionWrapper>
    </ContentLayout>
  );
}

const ProvidersTableFallback = () => {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-4">
        {/* ProviderTypeSelector */}
        <Skeleton className="h-[52px] min-w-[200px] flex-1 rounded-lg md:max-w-[280px]" />
        {/* Organizations filter */}
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        {/* Account Groups filter */}
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        {/* Status filter */}
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        {/* Action buttons */}
        <div className="ml-auto flex flex-wrap gap-4">
          <Skeleton className="h-9 w-[160px] rounded-md" />
          <Skeleton className="h-9 w-[120px] rounded-md" />
        </div>
      </div>
      <SkeletonTableProviders />
    </div>
  );
};

const AccountGroupsFallback = () => {
  return (
    <div className="grid min-h-[50vh] grid-cols-1 items-start gap-8 md:grid-cols-12">
      <div className="col-span-1 md:col-span-4">
        <div className="flex flex-col gap-4">
          <Skeleton className="h-7 w-48 rounded" />
          <Skeleton className="h-4 w-64 rounded" />
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-full rounded-md" />
          <Skeleton className="h-10 w-32 rounded-md" />
        </div>
      </div>
      <div className="col-span-1 md:col-span-1" />
      <div className="col-span-1 md:col-span-6">
        <SkeletonTableProviders />
      </div>
    </div>
  );
};

const ProvidersAccountsContent = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providersView = await loadProvidersAccountsViewData({
    searchParams,
    isCloud: process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true",
  });

  return (
    <ProvidersAccountsView
      isCloud={process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true"}
      filters={providersView.filters}
      providers={providersView.providers}
      metadata={providersView.metadata}
      rows={providersView.rows}
    />
  );
};
