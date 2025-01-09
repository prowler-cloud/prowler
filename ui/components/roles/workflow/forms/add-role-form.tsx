"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Checkbox, Divider } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { addRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomDropdownSelection,
  CustomInput,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { addRoleFormSchema, ApiError } from "@/types";

type FormValues = z.infer<typeof addRoleFormSchema>;

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
      manage_account: false,
      manage_billing: false,
      manage_providers: false,
      manage_integrations: false,
      manage_scans: false,
      unlimited_visibility: false,
      groups: [],
    },
  });

  const manageProviders = form.watch("manage_providers");
  const unlimitedVisibility = form.watch("unlimited_visibility");

  useEffect(() => {
    if (manageProviders) {
      form.setValue("unlimited_visibility", true, {
        shouldValidate: true,
        shouldDirty: true,
        shouldTouch: true,
      });
    }
  }, [manageProviders, form]);

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
    formData.append("manage_account", String(values.manage_account));
    formData.append("manage_billing", String(values.manage_billing));
    formData.append("manage_providers", String(values.manage_providers));
    formData.append("manage_integrations", String(values.manage_integrations));
    formData.append("manage_scans", String(values.manage_scans));
    formData.append(
      "unlimited_visibility",
      String(values.unlimited_visibility),
    );

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
          title: "Role Added",
          description: "The role was added successfully.",
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

  const permissions = [
    { field: "manage_users", label: "Invite and Manage Users" },
    { field: "manage_account", label: "Manage Account" },
    { field: "manage_billing", label: "Manage Billing" },
    { field: "manage_providers", label: "Manage Cloud Providers" },
    { field: "manage_integrations", label: "Manage Integrations" },
    { field: "manage_scans", label: "Manage Scans" },
    { field: "unlimited_visibility", label: "Unlimited Visibility" },
  ];

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
            isSelected={permissions.every((perm) =>
              form.watch(perm.field as keyof FormValues),
            )}
            onChange={(e) => onSelectAllChange(e.target.checked)}
            classNames={{
              label: "text-small",
            }}
          >
            Grant all admin permissions
          </Checkbox>

          {/* Permissions Grid */}
          <div className="grid grid-cols-2 gap-4">
            {permissions.map(({ field, label }) => (
              <Checkbox
                key={field}
                {...form.register(field as keyof FormValues)}
                isSelected={!!form.watch(field as keyof FormValues)}
                classNames={{
                  label: "text-small",
                }}
              >
                {label}
              </Checkbox>
            ))}
          </div>
        </div>
        <Divider className="my-4" />

        {!unlimitedVisibility && (
          <div className="flex flex-col space-y-4">
            <span className="text-lg font-semibold">
              Groups and Account Visibility
            </span>

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
                  selectedKeys={field.value || []}
                  onChange={(name, selectedValues) =>
                    field.onChange(selectedValues)
                  }
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
            ariaLabel="Add Role"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Add Role</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
