"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { updateRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import { useManageProvidersUnlimitedVisibility } from "@/hooks/use-manage-providers-unlimited-visibility";
import { getErrorMessage } from "@/lib";
import {
  getUnlimitedVisibilityField,
  getVisiblePermissionFormFields,
} from "@/lib/role-permissions";
import { ApiError, editRoleFormSchema } from "@/types";

import { RoleForm, RoleFormValues } from "./role-form";

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
  groups: { id: string; name: string }[];
}) => {
  const { toast } = useToast();
  const router = useRouter();
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const visiblePermissionFormFields =
    getVisiblePermissionFormFields(isCloudEnvironment);
  const unlimitedVisibilityField = getUnlimitedVisibilityField();

  const form = useForm<RoleFormValues>({
    resolver: zodResolver(editRoleFormSchema),
    defaultValues: {
      ...roleData.data.attributes,
      groups:
        roleData.data.relationships?.provider_groups?.data.map((g) => g.id) ||
        [],
    },
  });

  const { setPermissionValue, setUnlimitedVisibility } =
    useManageProvidersUnlimitedVisibility(form);
  const unlimitedVisibility = form.watch("unlimited_visibility");

  const isLoading = form.formState.isSubmitting;

  const onSelectAllChange = (checked: boolean) => {
    visiblePermissionFormFields.forEach(({ field }) => {
      setPermissionValue(field, checked);
    });
  };

  const onSubmitClient = async (values: RoleFormValues) => {
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

      if (data?.errors && data.errors.length > 0) {
        data.errors.forEach((error: ApiError) => {
          const errorMessage = error.detail;
          const pointer = error.source?.pointer;
          switch (pointer) {
            case "/data/attributes/name":
              form.setError("name", {
                type: "server",
                message: errorMessage,
              });
              break;
            default:
              toast({
                variant: "destructive",
                title: "Error",
                description: errorMessage,
              });
          }
        });
      } else {
        toast({
          title: "Role Updated",
          description: "The role was updated successfully.",
        });
        router.push("/roles");
      }
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
      form={form}
      groups={groups}
      visiblePermissionFormFields={visiblePermissionFormFields}
      isLoading={isLoading}
      unlimitedVisibility={!!unlimitedVisibility}
      showUnlimitedVisibilityField={!!unlimitedVisibilityField}
      submitText="Update Role"
      onCancel={() => router.push("/roles")}
      onSubmit={onSubmitClient}
      onSelectAllChange={onSelectAllChange}
      setPermissionValue={setPermissionValue}
      setUnlimitedVisibility={setUnlimitedVisibility}
    />
  );
};
