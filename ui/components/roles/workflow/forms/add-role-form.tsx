"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";

import { addRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import { useManageProvidersUnlimitedVisibility } from "@/hooks/use-manage-providers-unlimited-visibility";
import { getErrorMessage } from "@/lib";
import {
  getUnlimitedVisibilityField,
  getVisiblePermissionFormFields,
} from "@/lib/role-permissions";
import { addRoleFormSchema, ApiError } from "@/types";

import { RoleForm, RoleFormValues } from "./role-form";

export const AddRoleForm = ({
  groups,
}: {
  groups: { id: string; name: string }[];
}) => {
  const { toast } = useToast();
  const router = useRouter();
  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const visiblePermissionFormFields =
    getVisiblePermissionFormFields(isCloudEnvironment);
  const unlimitedVisibilityField = getUnlimitedVisibilityField();

  const form = useForm<RoleFormValues>({
    resolver: zodResolver(addRoleFormSchema),
    defaultValues: {
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
          title: "Role Added",
          description: "The role was added successfully.",
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
      submitText="Add Role"
      onCancel={() => router.push("/roles")}
      onSubmit={onSubmitClient}
      onSelectAllChange={onSelectAllChange}
      setPermissionValue={setPermissionValue}
      setUnlimitedVisibility={setUnlimitedVisibility}
    />
  );
};
