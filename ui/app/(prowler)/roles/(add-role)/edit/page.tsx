import { redirect } from "next/navigation";
import React from "react";

import { EditRoleForm } from "@/components/roles/workflow/forms/edit-role-form";
import { SearchParamsProps } from "@/types";

export default function EditRolePage({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  if (!searchParams.roleId || Array.isArray(searchParams.roleId)) {
    redirect("/roles");
  }

  return <EditRoleForm roleId={searchParams.roleId} />;
}
