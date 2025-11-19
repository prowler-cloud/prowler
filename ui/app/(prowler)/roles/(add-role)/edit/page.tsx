import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getRoleInfoById } from "@/actions/roles/roles";
import { SkeletonRoleForm } from "@/components/roles/workflow";
import { EditRoleForm } from "@/components/roles/workflow/forms/edit-role-form";
import { SearchParamsProps } from "@/types";

export default async function EditRolePage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <Suspense key={searchParamsKey} fallback={<SkeletonRoleForm />}>
      <SSRDataRole searchParams={resolvedSearchParams} />
    </Suspense>
  );
}

const SSRDataRole = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const roleId = searchParams.roleId;

  if (!roleId || Array.isArray(roleId)) {
    redirect("/roles");
  }

  const roleData = await getRoleInfoById(roleId as string);

  if (!roleData || roleData.error) {
    return <div>Role not found</div>;
  }

  const groupsResponse = await getProviderGroups({});
  const groups =
    groupsResponse?.data?.map(
      (group: { id: string; attributes: { name: string } }) => ({
        id: group.id,
        name: group.attributes.name,
      }),
    ) || [];

  return <EditRoleForm roleId={roleId} roleData={roleData} groups={groups} />;
};
