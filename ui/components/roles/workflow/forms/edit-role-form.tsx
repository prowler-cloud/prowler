"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Checkbox, Divider, Tooltip } from "@nextui-org/react";
import { clsx } from "clsx";
import { InfoIcon, SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { updateRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomDropdownSelection,
  CustomInput,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { permissionFormFields } from "@/lib";
import { ApiError, editRoleFormSchema } from "@/types";

type FormValues = z.infer<typeof editRoleFormSchema>;

export const EditRoleForm = ({
  roleId,
  roleData,
  groups,
}: {
  roleId: string;
  roleData: {
    data: {
      attributes: FormValues;
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
  const form = useForm<FormValues>({
    resolver: zodResolver(editRoleFormSchema),
    defaultValues: {
      ...roleData.data.attributes,
      groups:
        roleData.data.relationships?.provider_groups?.data.map((g) => g.id) ||
        [],
    },
  });

  const { watch, setValue } = form;

  const manageProviders = watch("manage_providers");
  const unlimitedVisibility = watch("unlimited_visibility");

  useEffect(() => {
    if (manageProviders && !unlimitedVisibility) {
      setValue("unlimited_visibility", true, {
        shouldValidate: true,
        shouldDirty: true,
        shouldTouch: true,
      });
    }
  }, [manageProviders, unlimitedVisibility, setValue]);

  const isLoading = form.formState.isSubmitting;

  const onSelectAllChange = (checked: boolean) => {
    const permissions = [
      "manage_users",
      "manage_account",
      "manage_billing",
      "manage_providers",
      "manage_integrations",
      "manage_scans",
      "unlimited_visibility",
    ];
    permissions.forEach((permission) => {
      form.setValue(permission as keyof FormValues, checked, {
        shouldValidate: true,
        shouldDirty: true,
        shouldTouch: true,
      });
    });
  };

  const onSubmitClient = async (values: FormValues) => {
    try {
      const updatedFields: Partial<FormValues> = {};

      if (values.name !== roleData.data.attributes.name) {
        updatedFields.name = values.name;
      }

      updatedFields.manage_users = values.manage_users;
      updatedFields.manage_providers = values.manage_providers;
      updatedFields.manage_account = values.manage_account;
      // updatedFields.manage_integrations = values.manage_integrations;
      updatedFields.manage_scans = values.manage_scans;
      updatedFields.unlimited_visibility = values.unlimited_visibility;

      if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
        updatedFields.manage_billing = values.manage_billing;
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
          switch (error.source.pointer) {
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
        description: "An unexpected error occurred. Please try again.",
      });
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-6"
      >
        <CustomInput
          control={form.control}
          name="name"
          type="text"
          label="Role Name"
          labelPlacement="inside"
          placeholder="Enter role name"
          variant="bordered"
          isRequired
          isInvalid={!!form.formState.errors.name}
        />

        <div className="flex flex-col space-y-4">
          <span className="text-lg font-semibold">Admin Permissions</span>

          {/* Select All Checkbox */}
          <Checkbox
            isSelected={permissionFormFields.every((perm) =>
              form.watch(perm.field as keyof FormValues),
            )}
            onChange={(e) => onSelectAllChange(e.target.checked)}
            classNames={{
              label: "text-small",
              wrapper: "checkbox-update",
            }}
          >
            Grant all admin permissions
          </Checkbox>

          {/* Permissions Grid */}
          <div className="grid grid-cols-2 gap-4">
            {permissionFormFields
              .filter(
                (permission) =>
                  permission.field !== "manage_billing" ||
                  process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true",
              )
              .map(({ field, label, description }) => (
                <div key={field} className="flex items-center gap-2">
                  <Checkbox
                    {...form.register(field as keyof FormValues)}
                    isSelected={!!form.watch(field as keyof FormValues)}
                    classNames={{
                      label: "text-small",
                      wrapper: "checkbox-update",
                    }}
                  >
                    {label}
                  </Checkbox>
                  <Tooltip content={description} placement="right">
                    <div className="flex w-fit items-center justify-center">
                      <InfoIcon
                        className={clsx(
                          "cursor-pointer text-default-400 group-data-[selected=true]:text-foreground",
                        )}
                        aria-hidden={"true"}
                        width={16}
                      />
                    </div>
                  </Tooltip>
                </div>
              ))}
          </div>
        </div>
        <Divider className="my-4" />

        {!unlimitedVisibility && (
          <div className="flex flex-col space-y-4">
            <span className="text-lg font-semibold">Groups visibility</span>

            <p className="text-small font-medium text-default-700">
              Select the groups this role will have access to. If no groups are
              selected and unlimited visibility is not enabled, the role will
              not have access to any accounts.
            </p>

            <Controller
              name="groups"
              control={form.control}
              render={({ field }) => (
                <CustomDropdownSelection
                  label="Select Groups"
                  name="groups"
                  values={groups}
                  selectedKeys={field.value}
                  onChange={(name, selectedValues) => {
                    field.onChange(selectedValues);
                  }}
                />
              )}
            />

            {form.formState.errors.groups && (
              <p className="mt-2 text-sm text-red-600">
                {form.formState.errors.groups.message}
              </p>
            )}
          </div>
        )}
        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel="Update Role"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Update Role</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
