"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Dispatch, SetStateAction } from "react";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { updateScan } from "@/actions/scans";
import { useToast } from "@/components/ui";
import { CustomInput } from "@/components/ui/custom";
import { Form, FormButtons } from "@/components/ui/form";
import { editScanFormSchema } from "@/types";

export const EditScanForm = ({
  scanId,
  scanName,
  setIsOpen,
}: {
  scanId: string;
  scanName: string;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
}) => {
  const formSchema = editScanFormSchema(scanName);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      scanId: scanId,
      scanName: scanName || "",
    },
  });

  const { toast } = useToast();

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await updateScan(formData);

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
        description: "The scan was updated successfully.",
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
          Current name:{" "}
          <span className="font-bold">{scanName || "Unnamed"}</span>
        </div>
        <div>
          <CustomInput
            control={form.control}
            name="scanName"
            type="text"
            label="Name"
            labelPlacement="outside"
            placeholder={scanName || "Enter scan name"}
            variant="bordered"
            isRequired={false}
          />
        </div>
        <input type="hidden" name="scanId" value={scanId} />

        <FormButtons setIsOpen={setIsOpen} isDisabled={isLoading} />
      </form>
    </Form>
  );
};
