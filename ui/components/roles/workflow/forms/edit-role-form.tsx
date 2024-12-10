"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Checkbox } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { updateRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError, editRoleFormSchema } from "@/types";

export type FormValues = z.infer<typeof editRoleFormSchema>;

export const EditRoleForm = ({
  roleId,
  roleData,
}: {
  roleId: string;
  roleData: FormValues;
}) => {
  const { toast } = useToast();
  const router = useRouter();

  const form = useForm<FormValues>({
    resolver: zodResolver(editRoleFormSchema),
    defaultValues: roleData,
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
    if (!roleId) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Role ID is missing.",
      });
      return;
    }

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

    try {
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

  const permissions = [
    { field: "manage_users", label: "Invite and Manage Users" },
    { field: "manage_account", label: "Manage SaaS Account" },
    { field: "manage_billing", label: "Manage Billing" },
    { field: "manage_providers", label: "Manage Cloud Accounts" },
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
