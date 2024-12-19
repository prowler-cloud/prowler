import { Divider } from "@nextui-org/react";
import { redirect } from "next/navigation";
import React, { Suspense } from "react";

import {
  getProviderGroupInfoById,
  getProviderGroups,
} from "@/actions/manage-groups/manage-groups";
import { getProviders } from "@/actions/providers";
import { getRoles } from "@/actions/roles";
import { AddGroupForm, EditGroupForm } from "@/components/manage-groups/forms";
import { SkeletonManageGroups } from "@/components/manage-groups/skeleton-manage-groups";
import { ColumnGroups } from "@/components/manage-groups/table";
import { DataTable } from "@/components/ui/table";
import { ProviderProps, Role, SearchParamsProps } from "@/types";

export default function ManageGroupsPage({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams);
  const providerGroupId = searchParams.groupId;

  return (
    <div className="grid min-h-[70vh] grid-cols-1 items-center justify-center gap-4 md:grid-cols-12">
      <div className="col-span-1 flex justify-end md:col-span-4">
        <Suspense key={searchParamsKey} fallback={<SkeletonManageGroups />}>
          {providerGroupId ? (
            <SSRDataEditGroup searchParams={searchParams} />
          ) : (
            <SSRAddGroupForm />
          )}
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

const SSRDataEditGroup = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providerGroupId = searchParams.groupId;

  // Redirect if no group ID is provided or if the parameter is invalid
  if (!providerGroupId || Array.isArray(providerGroupId)) {
    redirect("/providers/manage-groups");
  }

  // Fetch the provider group details
  const providerGroupData = await getProviderGroupInfoById(
    providerGroupId as string,
  );

  // Handle errors if provider group data is not found
  if (!providerGroupData || providerGroupData.error) {
    return <div>Provider group not found</div>;
  }

  // Fetch the complete lists of providers and roles
  const providersResponse = await getProviders({});
  const rolesResponse = await getRoles({});

  // Map all providers into an array of { id, name }
  const providersList =
    providersResponse?.data.map((provider: ProviderProps) => ({
      id: provider.id,
      name: provider.attributes.alias,
    })) || [];

  // Map all roles into an array of { id, name }
  const rolesList =
    rolesResponse?.data.map((role: any) => ({
      id: role.id,
      name: role.attributes.name,
    })) || [];

  // Extract attributes and relationships from the group data
  const { attributes, relationships } = providerGroupData.data;

  // Map the group's provider relationships to include { id, name }
  const providers =
    relationships.providers?.data.map((provider: any) => {
      const matchingProvider = providersList.find(
        (p: ProviderProps) => p.id === provider.id,
      );
      return {
        id: provider.id,
        name: matchingProvider?.name || "Unknown Provider",
      };
    }) || [];

  // Map the group's role relationships to include { id, name }
  const roles =
    relationships.roles?.data.map((role: Role) => {
      const matchingRole = rolesList.find((r: Role) => r.id === role.id);
      return {
        id: role.id,
        name: matchingRole?.name || "Unknown Role",
      };
    }) || [];

  // Prepare the form data in the expected structure
  const formData = {
    name: attributes.name,
    providers,
    roles,
  };

  return (
    <EditGroupForm
      providerGroupId={providerGroupId}
      providerGroupData={formData}
    />
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
