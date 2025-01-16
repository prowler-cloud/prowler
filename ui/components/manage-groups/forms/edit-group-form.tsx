"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { Controller, useForm } from "react-hook-form";
import * as z from "zod";

import { updateProviderGroup } from "@/actions/manage-groups/manage-groups";
import { useToast } from "@/components/ui";
import {
  CustomButton,
  CustomDropdownSelection,
  CustomInput,
} from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ApiError } from "@/types";

const editGroupSchema = z.object({
  name: z.string().nonempty("Provider group name is required"),
  providers: z.array(z.object({ id: z.string(), name: z.string() })).optional(),
  roles: z.array(z.object({ id: z.string(), name: z.string() })).optional(),
});

export type FormValues = z.infer<typeof editGroupSchema>;

export const EditGroupForm = ({
  providerGroupId,
  providerGroupData,
  allProviders,
  allRoles,
}: {
  providerGroupId: string;
  providerGroupData: FormValues;
  allProviders: { id: string; name: string }[];
  allRoles: { id: string; name: string }[];
}) => {
  const { toast } = useToast();
  const router = useRouter();

  const form = useForm<FormValues>({
    resolver: zodResolver(editGroupSchema),
    defaultValues: providerGroupData,
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    try {
      const updatedFields: Partial<FormValues> = {};

      if (values.name !== providerGroupData.name) {
        updatedFields.name = values.name;
      }

      if (
        JSON.stringify(values.providers) !==
        JSON.stringify(providerGroupData.providers)
      ) {
        updatedFields.providers = values.providers;
      }

      if (
        JSON.stringify(values.roles) !== JSON.stringify(providerGroupData.roles)
      ) {
        updatedFields.roles = values.roles;
      }

      if (Object.keys(updatedFields).length === 0) {
        toast({
          title: "No changes detected",
          description: "No updates were made to the provider group.",
        });
        return;
      }

      const formData = new FormData();
      if (updatedFields.name) {
        formData.append("name", updatedFields.name);
      }
      if (updatedFields.providers) {
        const providersData = updatedFields.providers.map((provider) => ({
          id: provider.id,
          type: "providers",
        }));
        formData.append("providers", JSON.stringify(providersData));
      }
      if (updatedFields.roles) {
        const rolesData = updatedFields.roles.map((role) => ({
          id: role.id,
          type: "roles",
        }));
        formData.append("roles", JSON.stringify(rolesData));
      }

      const data = await updateProviderGroup(providerGroupId, formData);

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
        toast({
          title: "Success!",
          description: "The group was updated successfully.",
        });
        router.push("/manage-groups");
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
        {/* Field for the name */}
        <div className="flex flex-col gap-2">
          <CustomInput
            control={form.control}
            name="name"
            type="text"
            label="Provider group name"
            labelPlacement="inside"
            placeholder="Enter the provider group name"
            variant="bordered"
            isRequired
            isInvalid={!!form.formState.errors.name}
          />
        </div>

        {/* Providers selection */}
        <Controller
          name="providers"
          control={form.control}
          render={({ field }) => {
            const combinedProviders = [
              ...(providerGroupData.providers || []),
              ...allProviders.filter(
                (p) =>
                  !(providerGroupData.providers || []).some(
                    (sp) => sp.id === p.id,
                  ),
              ),
            ];

            return (
              <CustomDropdownSelection
                label="Select Providers"
                name="providers"
                values={combinedProviders}
                selectedKeys={field.value?.map((p) => p.id) || []}
                onChange={(name, selectedValues) => {
                  const selectedProviders = combinedProviders.filter(
                    (provider) => selectedValues.includes(provider.id),
                  );
                  field.onChange(selectedProviders);
                }}
              />
            );
          }}
        />
        {form.formState.errors.providers && (
          <p className="mt-2 text-sm text-red-600">
            {form.formState.errors.providers.message}
          </p>
        )}

        <Divider orientation="horizontal" className="mb-2" />
        <p className="text-small text-default-500">
          The roles associated with the group can be edited directly here or
          from the Roles page.
        </p>
        {/* Roles selection */}
        <Controller
          name="roles"
          control={form.control}
          render={({ field }) => {
            const combinedRoles = [
              ...(providerGroupData.roles || []),
              ...allRoles.filter(
                (r) =>
                  !(providerGroupData.roles || []).some((sr) => sr.id === r.id),
              ),
            ];

            return (
              <CustomDropdownSelection
                label="Select Roles"
                name="roles"
                values={combinedRoles}
                selectedKeys={field.value?.map((r) => r.id) || []}
                onChange={(name, selectedValues) => {
                  const selectedRoles = combinedRoles.filter((role) =>
                    selectedValues.includes(role.id),
                  );
                  field.onChange(selectedRoles);
                }}
              />
            );
          }}
        />
        {form.formState.errors.roles && (
          <p className="mt-2 text-sm text-red-600">
            {form.formState.errors.roles.message}
          </p>
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-fit bg-transparent"
            variant="faded"
            size="md"
            onPress={() => {
              router.push("/manage-groups");
            }}
            isDisabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>
          <CustomButton
            type="submit"
            ariaLabel="Update Group"
            className="w-1/2"
            variant="solid"
            color="action"
            size="md"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Update Group</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
