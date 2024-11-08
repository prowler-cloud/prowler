"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { scanOnDemand } from "@/actions/scans";
import { RocketIcon } from "@/components/icons";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { onDemandScanFormSchema } from "@/types";

import { SelectScanProvider } from "./select-scan-provider";

type ProviderInfo = {
  providerId: string;
  alias: string;
  providerType: string;
  uid: string;
  connected: boolean;
};

export const LaunchScanWorkflow = ({
  providers,
}: {
  providers: ProviderInfo[];
}) => {
  const formSchema = onDemandScanFormSchema();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId: "",
      scanName: "",
      scannerArgs: { checksToExecute: [] },
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();
    console.log(values);

    // Loop through form values and add to formData, converting objects to JSON strings
    Object.entries(values).forEach(
      ([key, value]) =>
        value !== undefined &&
        formData.append(
          key,
          typeof value === "object" ? JSON.stringify(value) : value,
        ),
    );

    const data = await scanOnDemand(formData);

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
        description: "The scan was launched successfully.",
      });
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="flex flex-col gap-2">
              <span className="text-sm text-default-500">Launch Scan</span>
              <SelectScanProvider
                providers={providers}
                control={form.control}
                name="providerId"
              />
            </div>
            <CustomInput
              control={form.control}
              name="scanName"
              type="text"
              label="Scan Name"
              labelPlacement="outside"
              placeholder="Scan Name"
              variant="bordered"
              isRequired={false}
              isInvalid={!!form.formState.errors.scanName}
            />
          </div>
        </div>
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
            ariaLabel="Start scan now"
            className="w-full"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <RocketIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Start now</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
