import { Suspense } from "react";

import { listScanConfigurations } from "@/actions/scan-configurations";
import { ProvidersAccountsView } from "@/components/providers";
import { SkeletonTableProviders } from "@/components/providers/table";
import { CliImportBanner } from "@/components/scans";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { FilterTransitionWrapper } from "@/contexts";
import { SearchParamsProps } from "@/types";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  type ScanConfigurationListState,
} from "@/types/scan-configurations";

import { ProviderGroupsContent } from "./provider-groups-content";
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
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

  // Exclude `tab` and `onboarding` from the key: tab switches must not re-suspend,
  // and `onboarding` is ephemeral (stripped via history.replaceState) — keeping it
  // would remount ProvidersAccountsView and reset the wizard mid-flow.
  const {
    tab: _tab,
    onboarding: _onboarding,
    ...stableParams
  } = resolvedSearchParams || {};
  const searchParamsKey = JSON.stringify(stableParams);

  return (
    <ContentLayout
      title="Providers"
      icon="lucide:cloud-cog"
      onboardingAction={{ flowId: "add-provider" }}
    >
      {isCloudEnvironment && <CliImportBanner className="mb-6" />}
      <FilterTransitionWrapper>
        <ProviderPageTabs
          activeTab={activeTab}
          providersContent={
            <Suspense
              key={`providers-${searchParamsKey}`}
              fallback={<ProvidersTableFallback />}
            >
              <ProvidersTabContent searchParams={resolvedSearchParams} />
            </Suspense>
          }
          providerGroupsContent={
            <Suspense
              key={`groups-${searchParamsKey}`}
              fallback={<ProviderGroupsFallback />}
            >
              <ProviderGroupsContent searchParams={resolvedSearchParams} />
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
        <Skeleton className="h-[52px] min-w-[200px] flex-1 rounded-lg md:max-w-[280px]" />
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        <Skeleton className="h-[52px] max-w-[240px] min-w-[180px] flex-1 rounded-lg" />
        <div className="ml-auto flex flex-wrap gap-4">
          <Skeleton className="h-9 w-[160px] rounded-md" />
          <Skeleton className="h-9 w-[120px] rounded-md" />
        </div>
      </div>
      <SkeletonTableProviders />
    </div>
  );
};

const ProviderGroupsFallback = () => {
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

const loadScanConfigs = async (
  isCloud: boolean,
): Promise<ScanConfigurationListState> => {
  if (!isCloud) {
    return { status: SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE, data: [] };
  }

  try {
    return {
      status: SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
      data: await listScanConfigurations(),
    };
  } catch (error) {
    console.error("Error loading provider scan configurations:", error);
    return { status: SCAN_CONFIGURATION_LIST_STATUS.UNAVAILABLE, data: [] };
  }
};

const ProvidersTabContent = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const isCloud = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const [providersView, scanConfigsState] = await Promise.all([
    loadProvidersAccountsViewData({ searchParams, isCloud }),
    loadScanConfigs(isCloud),
  ]);

  return (
    <ProvidersAccountsView
      isCloud={isCloud}
      filters={providersView.filters}
      providers={providersView.providers}
      providerGroups={providersView.providerGroups}
      metadata={providersView.metadata}
      rows={providersView.rows}
      scanConfigs={scanConfigsState.data}
      scanConfigStatus={scanConfigsState.status}
    />
  );
};
