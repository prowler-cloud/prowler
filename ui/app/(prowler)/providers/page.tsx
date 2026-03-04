import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { FilterControls, filterProviders } from "@/components/filters";
import { ManageGroupsButton } from "@/components/manage-groups";
import {
  AddProviderButton,
  MutedFindingsConfigButton,
} from "@/components/providers";
import {
  ColumnProviders,
  SkeletonTableProviders,
} from "@/components/providers/table";
import { ContentLayout } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { ProviderProps, SearchParamsProps } from "@/types";

export default async function Providers({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <ContentLayout title="Cloud Providers" icon="lucide:cloud-cog">
      <div className="flex flex-col gap-6">
        <FilterControls search customFilters={filterProviders || []} />
        <ProvidersActions />
        <Suspense key={searchParamsKey} fallback={<ProvidersTableFallback />}>
          <ProvidersTable searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
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
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-12">
        <SkeletonTableProviders />
      </div>
    </div>
  );
};

const ProvidersTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const sort = searchParams.sort?.toString();
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const providersData = await getProviders({
    query,
    page,
    sort,
    filters,
    pageSize,
  });

  const providerGroupDict =
    providersData?.included
      ?.filter((item: any) => item.type === "provider-groups")
      .reduce((acc: Record<string, string>, group: any) => {
        acc[group.id] = group.attributes.name;
        return acc;
      }, {}) || {};

  const enrichedProviders =
    providersData?.data?.map((provider: ProviderProps) => {
      const groupNames =
        provider.relationships?.provider_groups?.data?.map(
          (group: { id: string }) =>
            providerGroupDict[group.id] || "Unknown Group",
        ) || [];
      return { ...provider, groupNames };
    }) || [];

  return (
    <>
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <DataTable
            columns={ColumnProviders}
            data={enrichedProviders || []}
            metadata={providersData?.meta}
          />
        </div>
      </div>
    </>
  );
};
