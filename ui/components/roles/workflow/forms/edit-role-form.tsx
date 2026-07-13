"use client";

import { useRouter } from "next/navigation";
import { DefaultValues } from "react-hook-form";

import { updateRole } from "@/actions/roles/roles";
import { useToast } from "@/components/shadcn";
import { getErrorMessage } from "@/lib";
import { RoleFormValues } from "@/types";

import { RoleForm, RoleFormSubmitContext, RoleGroupOption } from "./role-form";

export const EditRoleForm = ({
  roleId,
  roleData,
  groups,
}: {
  roleId: string;
  roleData: {
    data: {
      attributes: RoleFormValues;
      relationships?: {
        provider_groups?: {
          data: Array<{ id: string; type: string }>;
        };
      };
    };
  };
  groups: RoleGroupOption[];
}) => {
  const { toast } = useToast();
  const router = useRouter();
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

  const defaultValues: DefaultValues<RoleFormValues> = {
    ...roleData.data.attributes,
    groups:
      roleData.data.relationships?.provider_groups?.data.map((g) => g.id) || [],
  };

  const onSubmit = async (
    values: RoleFormValues,
    { handleServerResponse }: RoleFormSubmitContext,
  ) => {
    try {
      const updatedFields: Partial<RoleFormValues> = {};

      if (values.name !== roleData.data.attributes.name) {
        updatedFields.name = values.name;
      }

      updatedFields.manage_users = values.manage_users;
      updatedFields.manage_providers = values.manage_providers;
      updatedFields.manage_account = values.manage_account;
      updatedFields.manage_integrations = values.manage_integrations;
      updatedFields.manage_scans = values.manage_scans;
      updatedFields.unlimited_visibility = values.unlimited_visibility;

      if (isCloudEnvironment) {
        updatedFields.manage_billing = values.manage_billing;
        updatedFields.manage_alerts = values.manage_alerts;
      }

      if (
        JSON.stringify(values.groups) !==
        JSON.stringify(
          roleData.data.relationships?.provider_groups?.data.map((g) => g.id),
        )
      ) {
        updatedFields.groups = values.groups;
      }

      const formData = new FormData();

      Object.entries(updatedFields).forEach(([key, value]) => {
        if (key === "groups" && Array.isArray(value)) {
          value.forEach((group) => {
            formData.append("groups[]", group);
          });
        } else {
          formData.append(key, String(value));
        }
      });

      const data = await updateRole(formData, roleId);
      if (!handleServerResponse(data)) return;

      toast({
        title: "Role Updated",
        description: "The role was updated successfully.",
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
      submitText="Update Role"
      onSubmit={onSubmit}
    />
  );
};
