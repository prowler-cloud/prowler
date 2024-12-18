import { Divider } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { getRoles } from "@/actions/roles";
import { AddGroupForm } from "@/components/manage-groups/forms";
import { SkeletonManageGroups } from "@/components/manage-groups/skeleton-manage-groups";
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
          <SSRAddGroupForm searchParams={searchParams} />
        </Suspense>
      </div>

      <Divider orientation="vertical" className="mx-auto h-full" />

      <div className="col-span-1 flex justify-start md:col-span-6">
        {/* Space to add the table */}
      </div>
    </div>
  );
}

const SSRAddGroupForm = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
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
