"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { InfoIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import {
  Controller,
  DefaultValues,
  useForm,
  UseFormReturn,
  useWatch,
} from "react-hook-form";

import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import {
  Form,
  FormButtons,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/shadcn/form";
import { Input } from "@/components/shadcn/input/input";
import { EnhancedMultiSelect } from "@/components/shadcn/select/enhanced-multi-select";
import { Separator } from "@/components/shadcn/separator/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { useManageProvidersUnlimitedVisibility } from "@/hooks/use-manage-providers-unlimited-visibility";
import {
  getUnlimitedVisibilityField,
  getVisiblePermissionFormFields,
} from "@/lib/role-permissions";
import { roleFormSchema, RoleFormValues } from "@/types";

import { UnlimitedVisibilityField } from "./unlimited-visibility-section";

export interface RoleGroupOption {
  id: string;
  name: string;
}

export interface RoleFormSubmitContext {
  form: UseFormReturn<RoleFormValues>;
  handleServerResponse: (data: unknown) => boolean;
}

interface RoleFormProps {
  groups: RoleGroupOption[];
  defaultValues: DefaultValues<RoleFormValues>;
  submitText: string;
  onSubmit: (
    values: RoleFormValues,
    ctx: RoleFormSubmitContext,
  ) => void | Promise<void>;
  onCancel?: () => void;
}

export const RoleForm = ({
  groups,
  defaultValues,
  submitText,
  onSubmit,
  onCancel,
}: RoleFormProps) => {
  const router = useRouter();

  const form = useForm<RoleFormValues>({
    resolver: zodResolver(roleFormSchema),
    defaultValues,
  });

  const isCloudEnvironment = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";
  const visiblePermissionFormFields =
    getVisiblePermissionFormFields(isCloudEnvironment);
  const showUnlimitedVisibilityField = !!getUnlimitedVisibilityField();

  const { setPermissionValue, setUnlimitedVisibility } =
    useManageProvidersUnlimitedVisibility(form);
  const { handleServerResponse } = useFormServerErrors(form, {
    "/data/attributes/name": "name",
  });

  // useWatch instead of form.watch: React Compiler can keep memoized JSX stale
  // when getter reads happen during render.
  const formValues = useWatch({ control: form.control });
  const unlimitedVisibility = !!formValues.unlimited_visibility;
  const isLoading = form.formState.isSubmitting;

  const onSelectAllChange = (checked: boolean) => {
    visiblePermissionFormFields.forEach(({ field }) => {
      setPermissionValue(field, checked);
    });
  };

  const handleCancel = onCancel ?? (() => router.push("/roles"));

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit((values) =>
          onSubmit(values, { form, handleServerResponse }),
        )}
        className="flex flex-col gap-6"
      >
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>
                Role Name <span className="text-text-error-primary">*</span>
              </FormLabel>
              <FormControl>
                <Input
                  placeholder="Enter role name"
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex flex-col gap-4">
          <span className="text-lg font-semibold">Admin Permissions</span>

          {/* Select All Checkbox */}
          <div className="flex items-center gap-2">
            <Checkbox
              id="select-all"
              size="sm"
              checked={visiblePermissionFormFields.every((perm) =>
                Boolean(formValues[perm.field as keyof RoleFormValues]),
              )}
              onCheckedChange={(checked) => onSelectAllChange(Boolean(checked))}
            />
            <label htmlFor="select-all" className="text-small">
              Grant all admin permissions
            </label>
          </div>

          {/* Permissions Grid */}
          <div className="grid grid-cols-2 gap-4">
            {visiblePermissionFormFields.map(
              ({ field, label, description }) => (
                <div key={field} className="flex items-center gap-2">
                  <Checkbox
                    id={field}
                    size="sm"
                    checked={!!formValues[field as keyof RoleFormValues]}
                    onCheckedChange={(checked) =>
                      setPermissionValue(field, Boolean(checked))
                    }
                  />
                  <label htmlFor={field} className="text-small">
                    {label}
                  </label>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div className="flex w-fit items-center justify-center">
                        <InfoIcon
                          className="text-muted-foreground cursor-pointer"
                          aria-hidden="true"
                          width={16}
                        />
                      </div>
                    </TooltipTrigger>
                    <TooltipContent side="right">{description}</TooltipContent>
                  </Tooltip>
                </div>
              ),
            )}
          </div>
        </div>

        <Separator className="my-4" />

        <div className="flex flex-col gap-4">
          <span className="text-lg font-semibold">Visibility</span>

          {showUnlimitedVisibilityField && (
            <UnlimitedVisibilityField
              isSelected={unlimitedVisibility}
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
          onCancel={handleCancel}
        />
      </form>
    </Form>
  );
};
