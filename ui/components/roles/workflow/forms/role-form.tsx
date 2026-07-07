import { Checkbox } from "@heroui/checkbox";
import { Divider } from "@heroui/divider";
import { Tooltip } from "@heroui/tooltip";
import { clsx } from "clsx";
import { InfoIcon } from "lucide-react";
import { Controller, UseFormReturn } from "react-hook-form";
import { z } from "zod";

import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";
import { addRoleFormSchema } from "@/types";

import { UnlimitedVisibilityField } from "./unlimited-visibility-section";

export type RoleFormValues = z.input<typeof addRoleFormSchema>;

interface RoleFormProps {
  form: UseFormReturn<RoleFormValues>;
  groups: { id: string; name: string }[];
  visiblePermissionFormFields: {
    field: string;
    label: string;
    description: string;
  }[];
  isLoading: boolean;
  unlimitedVisibility: boolean;
  showUnlimitedVisibilityField: boolean;
  submitText: string;
  onCancel: () => void;
  onSubmit: (values: RoleFormValues) => void | Promise<void>;
  onSelectAllChange: (checked: boolean) => void;
  setPermissionValue: (field: string, checked: boolean) => void;
  setUnlimitedVisibility: (checked: boolean) => void;
}

export const RoleForm = ({
  form,
  groups,
  visiblePermissionFormFields,
  isLoading,
  unlimitedVisibility,
  showUnlimitedVisibilityField,
  submitText,
  onCancel,
  onSubmit,
  onSelectAllChange,
  setPermissionValue,
  setUnlimitedVisibility,
}: RoleFormProps) => {
  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
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
            isSelected={visiblePermissionFormFields.every((perm) =>
              form.watch(perm.field as keyof RoleFormValues),
            )}
            onValueChange={onSelectAllChange}
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
            {visiblePermissionFormFields.map(
              ({ field, label, description }) => (
                <div key={field} className="flex items-center gap-2">
                  <Checkbox
                    {...form.register(field as keyof RoleFormValues)}
                    isSelected={!!form.watch(field as keyof RoleFormValues)}
                    onValueChange={(checked) =>
                      setPermissionValue(field, checked)
                    }
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
                        aria-hidden="true"
                        width={16}
                      />
                    </div>
                  </Tooltip>
                </div>
              ),
            )}
          </div>
        </div>

        <Divider className="my-4" />

        <div className="flex flex-col gap-4">
          <span className="text-lg font-semibold">Visibility</span>

          {showUnlimitedVisibilityField && (
            <UnlimitedVisibilityField
              isSelected={!!form.watch("unlimited_visibility")}
              onValueChange={setUnlimitedVisibility}
            />
          )}

          {!unlimitedVisibility && (
            <>
              <p className="text-small text-default-700 font-medium">
                Select the groups this role will have access to. If no groups
                are selected and unlimited visibility is not enabled, the role
                will not have access to any accounts.
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
            </>
          )}
        </div>
        <FormButtons
          submitText={submitText}
          isDisabled={isLoading}
          onCancel={onCancel}
        />
      </form>
    </Form>
  );
};
