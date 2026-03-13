"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AnimatePresence, motion } from "framer-motion";
import { useForm, useWatch } from "react-hook-form";
import * as z from "zod";

import { scanOnDemand } from "@/actions/scans";
import { RocketIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { CustomInput } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { onDemandScanFormSchema } from "@/types";

import { SCAN_LAUNCHED_EVENT } from "../table/scans/scans-table-with-polling";
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
  const formSchema = z.object({
    ...onDemandScanFormSchema().shape,
    scanName: z
      .union([
        z
          .string()
          .min(3, "Must be at least 3 characters")
          .max(32, "Must not exceed 32 characters"),
        z.literal(""),
      ])
      .optional(),
  });

  const form = useForm({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId: "",
      scanName: "",
      scannerArgs: undefined,
    },
  });

  const providerId = useWatch({ control: form.control, name: "providerId" });
  const hasProviderSelected = Boolean(providerId);

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: z.infer<typeof formSchema>) => {
    const formValues = { ...values };

    const formData = new FormData();

    // Loop through form values and add to formData
    Object.entries(formValues).forEach(
      ([key, value]) =>
        value !== undefined &&
        formData.append(
          key,
          typeof value === "object" ? JSON.stringify(value) : value,
        ),
    );

    const data = await scanOnDemand(formData);

    if (data?.error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: data.error,
      });
    } else {
      toast({
        title: "Success!",
        description: "The scan was launched successfully.",
      });
      // Reset form after successful submission
      form.reset();
      // Notify the scans table to refresh and pick up the new scan
      window.dispatchEvent(new Event(SCAN_LAUNCHED_EVENT));
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-wrap justify-start gap-4"
      >
        <div className="w-72">
          <SelectScanProvider
            providers={providers}
            control={form.control}
            name="providerId"
          />
        </div>
        <AnimatePresence>
          {hasProviderSelected && (
            <>
              <div className="flex flex-wrap gap-6 md:gap-4">
                <motion.div
                  initial={{ opacity: 0, x: -50 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -50 }}
                  transition={{ duration: 0.3 }}
                  className="h-[3.4rem] min-w-[15.2rem] self-end"
                >
                  <CustomInput
                    control={form.control}
                    name="scanName"
                    type="text"
                    label="Scan label (optional)"
                    labelPlacement="outside"
                    placeholder="Scan label"
                    size="sm"
                    variant="bordered"
                    isRequired={false}
                  />
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, x: -50 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -50 }}
                  transition={{ duration: 0.3 }}
                  className="flex items-end gap-4"
                >
                  <Button
                    type="submit"
                    size="default"
                    disabled={isLoading}
                    className="gap-2"
                  >
                    {!isLoading && <RocketIcon size={16} />}
                    {isLoading ? "Loading..." : "Start now"}
                  </Button>
                  <Button
                    type="button"
                    onClick={() => form.reset()}
                    variant="outline"
                    size="default"
                  >
                    Cancel
                  </Button>
                </motion.div>
              </div>
            </>
          )}
        </AnimatePresence>
      </form>
    </Form>
  );
};
