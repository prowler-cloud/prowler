"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { updateProvider } from "@/actions/providers";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { editProviderFormSchema } from "@/types";

export const EditForm = ({
  providerId,
  providerAlias,
  setIsOpen,
}: {
  providerId: string;
  providerAlias?: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editProviderFormSchema(providerAlias ?? "");

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      [ProviderCredentialFields.PROVIDER_ID]: providerId,
      [ProviderCredentialFields.PROVIDER_ALIAS]: providerAlias,
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await updateProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      const error = data.errors[0];
      const errorMessage = `${error.detail}`;
      // show error
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: errorMessage,
      });
    } else {
      toast({
        title: "Success!",
        description: "The provider was updated successfully.",
      });
      setIsOpen(false); // Close the modal on success
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-4"
      >
        <div className="text-md">
          Current alias: <span className="font-bold">{providerAlias}</span>
        </div>
        <div>
          <CustomInput
            control={form.control}
            name={ProviderCredentialFields.PROVIDER_ALIAS}
            type="text"
            label="Alias"
            labelPlacement="outside"
            placeholder={providerAlias}
            variant="bordered"
            isRequired={false}
          />
        </div>
        <input type="hidden" name="providerId" value={providerId} />

        <FormButtons setIsOpen={setIsOpen} isDisabled={isLoading} />
      </form>
    </Form>
  );
};
