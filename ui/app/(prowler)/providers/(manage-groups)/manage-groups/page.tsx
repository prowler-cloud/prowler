import { Divider } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getProviders } from "@/actions/providers";
import { getRoles } from "@/actions/roles";
import { AddGroupForm } from "@/components/manage-groups/forms";
import { SkeletonManageGroups } from "@/components/manage-groups/skeleton-manage-groups";
import { ColumnGroups } from "@/components/manage-groups/table";
import { DataTable } from "@/components/ui/table";
import { ProviderProps, SearchParamsProps } from "@/types";

export default function ManageGroupsPage({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams);

  return (
    <div className="grid min-h-[70vh] grid-cols-1 items-center justify-center gap-4 md:grid-cols-12">
      <div className="col-span-1 flex justify-end md:col-span-4">
        <Suspense key={searchParamsKey} fallback={<SkeletonManageGroups />}>
          <SSRAddGroupForm />
        </Suspense>
      </div>

      <Divider orientation="vertical" className="mx-auto h-full" />

      <div className="col-span-1 flex-col justify-start md:col-span-6">
        <Suspense key={searchParamsKey} fallback={<SkeletonManageGroups />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
      </div>
    </div>
  );
}

const SSRAddGroupForm = async () => {
  const providersResponse = await getProviders({});
  const rolesResponse = await getRoles({});

  const providersData = providersResponse?.data.map(
    (provider: ProviderProps) => ({
      id: provider.id,
      name: provider.attributes.alias,
    }),
  );

  const rolesData = rolesResponse?.data.map((role: any) => ({
    id: role.id,
    name: role.attributes.name,
  }));

  return (
    <AddGroupForm providers={providersData || []} roles={rolesData || []} />
  );
};

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const sort = searchParams.sort?.toString();

  // Convert filters to the correct type
  const filters: Record<string, string> = {};
  Object.entries(searchParams)
    .filter(([key]) => key.startsWith("filter["))
    .forEach(([key, value]) => {
      filters[key] = value?.toString() || "";
    });

  const query = (filters["filter[search]"] as string) || "";
  const providerGroupsData = await getProviderGroups({
    query,
    page,
    sort,
    filters,
  });
  return (
    <DataTable
      columns={ColumnGroups}
      data={providerGroupsData?.data || []}
      metadata={providerGroupsData?.meta}
    />
  );
};
