import React from "react";

import { getProviderGroups } from "@/actions/manage-groups/manage-groups";
import { AddRoleForm } from "@/components/roles/workflow/forms/add-role-form";
import { ProviderGroup } from "@/types";

export default async function AddRolePage() {
  const groupsResponse = await getProviderGroups({});

  const groupsData =
    groupsResponse?.data?.map((group: ProviderGroup) => ({
      id: group.id,
      name: group.attributes.name,
    })) || [];

  return <AddRoleForm groups={groupsData} />;
}
