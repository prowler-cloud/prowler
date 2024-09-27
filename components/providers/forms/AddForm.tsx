"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { addProvider } from "@/actions";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { addProviderFormSchema } from "@/types";

import { CustomRadioProvider } from "../CustomRadioProvider";

export const AddForm = ({
  setIsOpen,
}: {
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
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
    console.log(values);
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addProvider(formData);

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
        className="flex flex-col space-y-4"
      >
        <CustomRadioProvider control={form.control} />
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

        <div className="w-full flex justify-center sm:space-x-6">
          <CustomButton
            type="button"
            className="w-full bg-transparent"
            variant="faded"
            size="lg"
            radius="lg"
            onPress={() => setIsOpen(false)}
            disabled={isLoading}
          >
            <span>Cancel</span>
          </CustomButton>

          <CustomButton
            type="submit"
            className="w-full"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <SaveIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Confirm</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
