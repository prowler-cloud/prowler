"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { RocketIcon } from "lucide-react";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { scanOnDemand } from "@/actions/scans";
import { useToast } from "@/components/ui";
import { CustomButton, CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { onDemandScanFormSchema } from "@/types";

export const ScanOnDemandForm = ({
  providerId,
  scanName,
  scannerArgs,
  setIsOpen,
}: {
  providerId: string;
  scanName?: string;
  scannerArgs?: { checksToExecute: string[] };
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = onDemandScanFormSchema();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId: providerId,
      scanName: scanName,
      scannerArgs: scannerArgs,
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

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
      setIsOpen(false);
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />

        <div>
          <CustomInput
            control={form.control}
            name="scanName"
            type="text"
            label="Scan Name"
            labelPlacement="outside"
            placeholder={scanName}
            variant="bordered"
            isRequired={false}
            isInvalid={!!form.formState.errors.scanName}
          />
        </div>

        <div className="flex w-full justify-center sm:space-x-6">
          <CustomButton
            type="button"
            ariaLabel="Cancel"
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
            ariaLabel="Save"
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
