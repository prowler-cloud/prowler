"use client";

import { Checkbox } from "@heroui/checkbox";
import { Divider } from "@heroui/divider";
import { Tooltip } from "@heroui/tooltip";
import { zodResolver } from "@hookform/resolvers/zod";
import clsx from "clsx";
import { InfoIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { addRole } from "@/actions/roles/roles";
import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";
import { getErrorMessage, permissionFormFields } from "@/lib";
import { addRoleFormSchema, ApiError } from "@/types";

type FormValues = z.input<typeof addRoleFormSchema>;

export const AddRoleForm = ({
  groups,
}: {
  groups: { id: string; name: string }[];
}) => {
  const { toast } = useToast();
  const router = useRouter();

  const form = useForm<FormValues>({
    resolver: zodResolver(addRoleFormSchema),
    defaultValues: {
      name: "",
      manage_users: false,
      manage_providers: false,
      manage_integrations: false,
      manage_scans: false,
      unlimited_visibility: false,
      groups: [],
      ...(process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true" && {
        manage_billing: false,
      }),
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

    // Conditionally append manage_account and manage_billing
    if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
      formData.append("manage_billing", String(values.manage_billing));
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
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-6"
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
        />

        <div className="flex flex-col gap-4">
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
            color="default"
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
                    color="default"
                  >
                    {label}
                  </Checkbox>
                  <Tooltip content={description} placement="right">
                    <div className="flex w-fit items-center justify-center">
                      <InfoIcon
                        className={clsx(
                          "text-default-400 group-data-[selected=true]:text-foreground cursor-pointer",
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
          <div className="flex flex-col gap-4">
            <span className="text-lg font-semibold">
              Groups and Account Visibility
            </span>

            <p className="text-small text-default-700 font-medium">
              Select the groups this role will have access to. If no groups are
              selected and unlimited visibility is not enabled, the role will
              not have access to any accounts.
            </p>

            <Controller
              name="groups"
              control={form.control}
              render={({ field }) => (
                <div className="flex flex-col gap-2">
                  <EnhancedMultiSelect
                    options={groups.map((group) => ({
                      label: group.name,
                      value: group.id,
                    }))}
                    onValueChange={field.onChange}
                    defaultValue={field.value || []}
                    placeholder="Select groups"
                    searchable={true}
                    hideSelectAll={true}
                    emptyIndicator="No results found"
                    resetOnDefaultValueChange={true}
                  />
                </div>
              )}
            />
            {form.formState.errors.groups && (
              <p className="mt-2 text-sm text-red-600">
                {form.formState.errors.groups.message}
              </p>
            )}
          </div>
        )}
        <FormButtons submitText="Add Role" isDisabled={isLoading} />
      </form>
    </Form>
  );
};
