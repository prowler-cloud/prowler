"use client";

import { useRouter } from "next/navigation";
import { DefaultValues } from "react-hook-form";

import { addRole } from "@/actions/roles/roles";
import { useToast } from "@/components/shadcn";
import { getErrorMessage } from "@/lib";
import { RoleFormValues } from "@/types";

import { RoleForm, RoleFormSubmitContext, RoleGroupOption } from "./role-form";

export const AddRoleForm = ({ groups }: { groups: RoleGroupOption[] }) => {
  const { toast } = useToast();
  const router = useRouter();
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

  const defaultValues: DefaultValues<RoleFormValues> = {
    name: "",
    manage_users: false,
    manage_providers: false,
    manage_integrations: false,
    manage_scans: false,
    unlimited_visibility: false,
    groups: [],
    ...(isCloudEnvironment && {
      manage_billing: false,
      manage_alerts: false,
    }),
  };

  const onSubmit = async (
    values: RoleFormValues,
    { handleServerResponse }: RoleFormSubmitContext,
  ) => {
    const formData = new FormData();

    formData.append("name", values.name);
    formData.append("manage_users", String(values.manage_users));
    formData.append("manage_providers", String(values.manage_providers));
    formData.append("manage_integrations", String(values.manage_integrations));
    formData.append("manage_scans", String(values.manage_scans));
    formData.append("manage_account", String(values.manage_account));
    formData.append(
      "unlimited_visibility",
      String(values.unlimited_visibility),
    );

    // Conditionally append Prowler Cloud permissions.
    if (isCloudEnvironment) {
      formData.append("manage_billing", String(values.manage_billing));
      formData.append("manage_alerts", String(values.manage_alerts));
    }

    if (values.groups && values.groups.length > 0) {
      values.groups.forEach((group) => {
        formData.append("groups[]", group);
      });
    }

    try {
      const data = await addRole(formData);
      if (!handleServerResponse(data)) return;

      toast({
        title: "Role Added",
        description: "The role was added successfully.",
      });
      router.push("/roles");
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: getErrorMessage(error),
      });
    }
  };

  return (
    <RoleForm
      groups={groups}
      defaultValues={defaultValues}
      submitText="Add Role"
      onSubmit={onSubmit}
    />
  );
};
