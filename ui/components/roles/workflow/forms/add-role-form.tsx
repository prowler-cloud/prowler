"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Checkbox } from "@nextui-org/react";
import { SaveIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { addRole } from "@/actions/roles/roles";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { addRoleFormSchema, ApiError } from "@/types";

export type FormValues = z.infer<typeof addRoleFormSchema>;

export const AddRoleForm = () => {
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
    },
  });

  const isLoading = form.formState.isSubmitting;

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
          variant: "success",
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

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
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

        {[
          "manage_users",
          "manage_account",
          "manage_billing",
          "manage_providers",
          "manage_integrations",
          "manage_scans",
          "unlimited_visibility",
        ].map((field) => (
          <Checkbox key={field} {...form.register(field as keyof FormValues)}>
            {field.replace("_", " ")}
          </Checkbox>
        ))}

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
