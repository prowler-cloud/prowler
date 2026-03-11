import {
  getProviderGroupInfoById,
  getProviderGroups,
} from "@/actions/manage-groups/manage-groups";
import { getProviders } from "@/actions/providers";
import { getRoles } from "@/actions/roles";
import { AddGroupForm, EditGroupForm } from "@/components/manage-groups/forms";
import { ColumnGroups } from "@/components/manage-groups/table";
import { DataTable } from "@/components/ui/table";
import { ProviderProps, Role, SearchParamsProps } from "@/types";

export const AccountGroupsContent = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providerGroupId = searchParams.groupId;

  // Fetch all data in parallel
  const [providersResponse, rolesResponse, providerGroupsData, editGroupData] =
    await Promise.all([
      getProviders({ pageSize: 50 }),
      getRoles({}),
      fetchGroupsTableData(searchParams),
      providerGroupId && !Array.isArray(providerGroupId)
        ? getProviderGroupInfoById(providerGroupId)
        : Promise.resolve(null),
    ]);

  const providersList =
    providersResponse?.data?.map((provider: ProviderProps) => ({
      id: provider.id,
      name: provider.attributes.alias || provider.attributes.uid,
    })) || [];

  const rolesList =
    rolesResponse?.data?.map((role: Role) => ({
      id: role.id,
      name: role.attributes.name,
    })) || [];

  return (
    <div className="grid min-h-[50vh] grid-cols-1 items-start gap-8 md:grid-cols-12">
      {/* Left: Form (Add or Edit) */}
      <div className="col-span-1 md:col-span-4">
        {providerGroupId && editGroupData?.data ? (
          <EditGroupSection
            providerGroupId={
              Array.isArray(providerGroupId)
                ? providerGroupId[0]
                : providerGroupId
            }
            groupData={editGroupData.data}
            allProviders={providersList}
            allRoles={rolesList}
          />
        ) : (
          <div className="flex flex-col">
            <h1 className="mb-2 text-xl font-medium">
              Create a new account group
            </h1>
            <p className="text-text-neutral-tertiary mb-5 text-sm">
              Create a new account group to manage the providers and roles.
            </p>
            <AddGroupForm providers={providersList} roles={rolesList} />
          </div>
        )}
      </div>

      {/* Divider */}
      <div className="border-border-neutral-secondary hidden md:col-span-1 md:flex md:justify-center">
        <div className="border-border-neutral-secondary h-full border-l" />
      </div>

      {/* Right: Table */}
      <div className="col-span-1 md:col-span-7">
        <DataTable
          columns={ColumnGroups}
          data={providerGroupsData?.data || []}
          metadata={providerGroupsData?.meta}
        />
      </div>
    </div>
  );
};

interface EditGroupRelationships {
  providers?: { data: ProviderProps[] };
  roles?: { data: Role[] };
}

interface EditGroupData {
  attributes: { name: string };
  relationships: EditGroupRelationships;
}

const EditGroupSection = ({
  providerGroupId,
  groupData,
  allProviders,
  allRoles,
}: {
  providerGroupId: string;
  groupData: EditGroupData;
  allProviders: { id: string; name: string }[];
  allRoles: { id: string; name: string }[];
}) => {
  const { attributes, relationships } = groupData;

  const associatedProviders = relationships.providers?.data.map(
    (provider: ProviderProps) => {
      const match = allProviders.find((p) => p.id === provider.id);
      return {
        id: provider.id,
        name: match?.name || "Unavailable for your role",
      };
    },
  );

  const associatedRoles = relationships.roles?.data.map((role: Role) => {
    const match = allRoles.find((r) => r.id === role.id);
    return {
      id: role.id,
      name: match?.name || "Unavailable for your role",
    };
  });

  return (
    <div className="flex flex-col">
      <h1 className="mb-2 text-xl font-medium">Edit account group</h1>
      <p className="text-text-neutral-tertiary mb-5 text-sm">
        Edit the account group to manage the providers and roles.
      </p>
      <EditGroupForm
        providerGroupId={providerGroupId}
        providerGroupData={{
          name: attributes.name,
          providers: associatedProviders,
          roles: associatedRoles,
        }}
        allProviders={allProviders}
        allRoles={allRoles}
      />
    </div>
  );
};

const fetchGroupsTableData = async (searchParams: SearchParamsProps) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const sort = searchParams.sort?.toString();
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);

  const filters: Record<string, string> = {};
  Object.entries(searchParams)
    .filter(([key]) => key.startsWith("filter["))
    .forEach(([key, value]) => {
      filters[key] = value?.toString() || "";
    });

  const query = (filters["filter[search]"] as string) || "";
  return getProviderGroups({ query, page, sort, filters, pageSize });
};
