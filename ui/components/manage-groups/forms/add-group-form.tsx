"use client";
import { Divider } from "@heroui/divider";
import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { createProviderGroup } from "@/actions/manage-groups";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { CustomDropdownSelection, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError } from "@/types";

const addGroupSchema = z.object({
  name: z.string().min(1, "Provider group name is required"),
  providers: z.array(z.string()).optional(),
  roles: z.array(z.string()).optional(),
});

type FormValues = z.infer<typeof addGroupSchema>;

export const AddGroupForm = ({
  roles = [],
  providers = [],
}: {
  roles: Array<{ id: string; name: string }>;
  providers: Array<{ id: string; name: string }>;
}) => {
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(addGroupSchema),
    defaultValues: {
      name: "",
      providers: [],
      roles: [],
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    try {
      const formData = new FormData();
      formData.append("name", values.name);

      if (values.providers?.length) {
        const providersData = values.providers.map((id) => ({
          id,
          type: "providers",
        }));
        formData.append("providers", JSON.stringify(providersData));
      }

      if (values.roles?.length) {
        const rolesData = values.roles.map((id) => ({
          id,
          type: "roles",
        }));
        formData.append("roles", JSON.stringify(rolesData));
      }

      const data = await createProviderGroup(formData);

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
            case "/data/relationships/roles":
              form.setError("roles", {
                type: "server",
                message: errorMessage,
              });
              break;
            default:
              toast({
                variant: "destructive",
                title: "Oops! Something went wrong",
                description: errorMessage,
              });
          }
        });
      } else {
        form.reset();
        toast({
          title: "Success!",
          description: "The group was created successfully.",
        });
      }
    } catch (_error) {
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
        className="flex flex-col gap-4"
      >
        <div className="flex flex-col gap-2">
          <CustomInput
            control={form.control}
            name="name"
            type="text"
            label="Provider group name"
            labelPlacement="inside"
            placeholder="Enter the provider group name"
            variant="flat"
            isRequired
          />
        </div>

        {/*Select Providers */}
        <Controller
          name="providers"
          control={form.control}
          render={({ field }) => (
            <CustomDropdownSelection
              label="Select Providers"
              name="providers"
              values={providers}
              selectedKeys={field.value || []}
              onChange={(name, selectedValues) =>
                field.onChange(selectedValues)
              }
            />
          )}
        />
        {form.formState.errors.providers && (
          <p className="mt-2 text-sm text-red-600">
            {form.formState.errors.providers.message}
          </p>
        )}
        <Divider orientation="horizontal" className="mb-2" />

        <p className="text-small text-default-500">
          Roles can also be associated with the group. This step is optional and
          can be completed later if needed or from the Roles page.
        </p>
        {/* Select Roles */}
        <Controller
          name="roles"
          control={form.control}
          render={({ field }) => (
            <CustomDropdownSelection
              label="Select Roles"
              name="roles"
              values={roles}
              selectedKeys={field.value || []}
              onChange={(name, selectedValues) =>
                field.onChange(selectedValues)
              }
            />
          )}
        />
        {form.formState.errors.roles && (
          <p className="mt-2 text-sm text-red-600">
            {form.formState.errors.roles.message}
          </p>
        )}

        {/* Submit Button */}
        <div className="flex w-full justify-end sm:gap-6">
          <Button type="submit" className="w-1/2" disabled={isLoading}>
            {!isLoading && <SaveIcon size={24} />}
            {isLoading ? "Loading" : "Create Group"}
          </Button>
        </div>
      </form>
    </Form>
  );
};
