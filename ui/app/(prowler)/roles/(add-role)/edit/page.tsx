import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getRoleInfoById } from "@/actions/roles/roles";
import { SkeletonRoleForm } from "@/components/roles/workflow";
import { EditRoleForm } from "@/components/roles/workflow/forms/edit-role-form";
import { SearchParamsProps } from "@/types";

export default async function EditRolePage({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <Suspense key={searchParamsKey} fallback={<SkeletonRoleForm />}>
      <SSRDataRole searchParams={searchParams} />
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

  const { attributes } = roleData.data;

  return <EditRoleForm roleId={roleId} roleData={attributes} />;
};
