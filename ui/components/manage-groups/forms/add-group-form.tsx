"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { createProviderGroup } from "@/actions/manage-groups";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomDropdownSelection,
  CustomInput,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError } from "@/types";

const addGroupSchema = z.object({
  name: z.string().nonempty("Provider group name is required"),
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
          switch (error.source.pointer) {
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
        className="flex flex-col space-y-4"
      >
        {/* Name Field */}
        <p className="text-small font-medium text-default-700">
          Please provide a name for the group. You can also select providers and
          roles to associate with the group, this step is optional and can be
          done later if needed.
        </p>
        <Divider orientation="horizontal" className="mb-2" />
        <div className="flex flex-col gap-2">
          <CustomInput
            control={form.control}
            name="name"
            type="text"
            label="Provider group name"
            labelPlacement="outside"
            placeholder="Enter the provider group name"
            variant="bordered"
            isRequired
            isInvalid={!!form.formState.errors.name}
          />
        </div>

        {/* Providers Field */}
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

        {/* Roles Field */}
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
        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel="Create Group"
            className="w-1/2"
            variant="solid"
            color="action"
            size="md"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Create Group</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
