import { Suspense } from "react";

import { ManageGroupsButton } from "@/components/manage-groups";
import {
  AddProviderButton,
  MutedFindingsConfigButton,
  ProvidersAccountsTable,
  ProvidersFilters,
} from "@/components/providers";
import { SkeletonTableProviders } from "@/components/providers/table";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
import { SearchParamsProps } from "@/types";

import { loadProvidersAccountsViewData } from "./providers-page.utils";

export default async function Providers({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <ContentLayout title="Cloud Providers" icon="lucide:cloud-cog">
      <FilterTransitionWrapper>
        <Suspense key={searchParamsKey} fallback={<ProvidersTableFallback />}>
          <ProvidersTable searchParams={resolvedSearchParams} />
        </Suspense>
      </FilterTransitionWrapper>
    </ContentLayout>
  );
}

const ProvidersActions = () => {
  return (
    <div className="flex flex-wrap gap-4 md:justify-end">
      <ManageGroupsButton />
      <MutedFindingsConfigButton />
      <AddProviderButton />
    </div>
  );
};

const ProvidersTableFallback = () => {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <Skeleton className="h-5 w-16 rounded" />
          </div>
          <div className="flex flex-wrap gap-3">
            <Skeleton className="h-10 w-36 rounded-md" />
            <Skeleton className="h-10 w-40 rounded-md" />
            <Skeleton className="h-10 w-36 rounded-md" />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <Skeleton className="h-10 w-[280px] rounded-md" />
          <Skeleton className="h-10 w-[200px] rounded-md" />
          <Skeleton className="h-10 w-[200px] rounded-md" />
          <Skeleton className="h-10 w-[180px] rounded-md" />
        </div>
      </div>
      <SkeletonTableProviders />
    </div>
  );
};

const ProvidersTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providersView = await loadProvidersAccountsViewData({
    searchParams,
    isCloud: process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true",
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-6">
          <button
            type="button"
            className="border-button-primary text-text-neutral-primary border-b-2 pb-2 text-sm font-medium"
          >
            Accounts
          </button>
        </div>
        <ProvidersActions />
      </div>
      <ProvidersFilters
        filters={providersView.filters}
        providers={providersView.providers}
      />
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <ProvidersAccountsTable
            isCloud={process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true"}
            metadata={providersView.metadata}
            rows={providersView.rows}
          />
        </div>
      </div>
    </div>
  );
};
