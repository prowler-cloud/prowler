"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { updateTenantName } from "@/actions/users/tenants";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

const editTenantFormSchema = (currentName: string) =>
  z.object({
    tenantId: z.string(),
    name: z
      .string()
      .min(1, { message: "Name is required" })
      .refine((val) => val !== currentName, {
        message: "Name must be different from the current name",
      }),
  });

export const EditTenantForm = ({
  tenantId,
  tenantName,
  setIsOpen,
}: {
  tenantId: string;
  tenantName?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editTenantFormSchema(tenantName ?? "");

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tenantId: tenantId,
      name: "",
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await updateTenantName(formData);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Changed successfully",
        description: "Tenant name updated successfully.",
      });
      setIsOpen(false);
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="text-md">
          Current name: <span className="font-bold">{tenantName}</span>
        </div>
        <div>
          <CustomInput
            control={form.control}
            name="name"
            type="text"
            label="Organization name"
            labelPlacement="outside"
            placeholder="Enter the new name"
            variant="bordered"
            isRequired={true}
            isInvalid={!!form.formState.errors.name}
          />
        </div>
        <input type="hidden" name="tenantId" value={tenantId} />

        <div className="flex w-full justify-center space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            onPress={() => setIsOpen(false)}
            isDisabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="submit"
            ariaLabel="Save"
            className="w-full"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Save</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
