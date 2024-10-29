"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { SaveIcon } from "lucide-react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";

import { addProvider } from "../../../../actions/providers/providers";
import { addProviderFormSchema, ApiError } from "../../../../types";
import { RadioGroupProvider } from "../../radio-group-provider";

export const ConnectAccountForm = () => {
  const formSchema = addProviderFormSchema;

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerType: "",
      providerId: "",
      providerAlias: "",
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        switch (error.source.pointer) {
          case "/data/attributes/provider":
            form.setError("providerType", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/uid":
            form.setError("providerId", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/alias":
            form.setError("providerAlias", {
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
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <RadioGroupProvider
          control={form.control}
          isInvalid={!!form.formState.errors.providerType}
        />
        <CustomInput
          control={form.control}
          name="providerId"
          type="text"
          label="Provider ID"
          labelPlacement="inside"
          placeholder={"Enter the provider ID"}
          variant="bordered"
          isRequired
          isInvalid={!!form.formState.errors.providerId}
        />
        <CustomInput
          control={form.control}
          name="providerAlias"
          type="text"
          label="Alias"
          labelPlacement="inside"
          placeholder={"Enter the provider alias"}
          variant="bordered"
          isRequired={false}
          isInvalid={!!form.formState.errors.providerAlias}
        />

        <div className="flex w-full justify-center sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            isDisabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="submit"
            ariaLabel="Next"
            className="w-full"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Next</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
