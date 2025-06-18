import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { FilterControls, filterProviders } from "@/components/filters";
import { ManageGroupsButton } from "@/components/manage-groups";
import { AddProviderButton } from "@/components/providers";
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
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <ContentLayout title="Cloud Providers" icon="fluent:cloud-sync-24-regular">
      <FilterControls search customFilters={filterProviders || []} />
      <Spacer y={8} />
      <div className="flex items-center gap-4 md:justify-end">
        <ManageGroupsButton />
        <AddProviderButton />
      </div>
      <Spacer y={8} />

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableProviders />}>
            <SSRDataTable searchParams={searchParams} />
          </Suspense>
        </div>
      </div>
    </ContentLayout>
  );
}

const SSRDataTable = async ({
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
    <DataTable
      columns={ColumnProviders}
      data={enrichedProviders || []}
      metadata={providersData?.meta}
    />
  );
};
