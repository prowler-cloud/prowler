"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import { AnimatePresence, motion } from "framer-motion";
import { useForm } from "react-hook-form";
import * as z from "zod";

import { scanOnDemand } from "@/actions/scans";
import { RocketIcon, ScheduleIcon } from "@/components/icons";
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
      scannerArgs: undefined,
    },
  });

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
        title: "Success!",
        description: "The scan was launched successfully.",
      });
      // Reset form after successful submission
      form.reset();
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="grid grid-cols-2 gap-6">
          <div className="flex flex-col gap-6">
            <div className="w-full">
              <p className="pb-1 text-sm font-medium text-default-700">
                Launch Scan
              </p>
              <SelectScanProvider
                providers={providers}
                control={form.control}
                name="providerId"
              />
            </div>

            <AnimatePresence>
              {form.watch("providerId") && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <CustomInput
                    control={form.control}
                    name="scanName"
                    type="text"
                    label="Scan Name (optional)"
                    labelPlacement="outside"
                    placeholder="Scan Name"
                    variant="bordered"
                    isRequired={false}
                    isInvalid={!!form.formState.errors.scanName}
                  />
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="flex flex-col justify-start">
            <AnimatePresence>
              {form.watch("providerId") && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <CustomInput
                    control={form.control}
                    name="scannerArgs"
                    type="text"
                    label="Scanner Args (optional)"
                    labelPlacement="outside"
                    placeholder="Scanner Args"
                    variant="bordered"
                    isRequired={false}
                    isInvalid={!!form.formState.errors.scannerArgs}
                  />
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <AnimatePresence>
            {form.watch("providerId") && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className="col-span-2 flex justify-start gap-4"
              >
                <CustomButton
                  onPress={() => form.reset()}
                  className="w-fit border-gray-200 bg-transparent"
                  ariaLabel="Clear form"
                  variant="bordered"
                  size="lg"
                  radius="lg"
                >
                  Cancel
                </CustomButton>
                <CustomButton
                  type="submit"
                  ariaLabel="Schedule scan"
                  variant="solid"
                  color="action"
                  size="lg"
                  isLoading={isLoading}
                  startContent={!isLoading && <ScheduleIcon size={24} />}
                  isDisabled={true}
                >
                  {isLoading ? <>Loading</> : <span>Schedule</span>}
                </CustomButton>

                <CustomButton
                  type="submit"
                  ariaLabel="Start scan now"
                  variant="solid"
                  color="action"
                  size="lg"
                  isLoading={isLoading}
                  startContent={!isLoading && <RocketIcon size={24} />}
                >
                  {isLoading ? <>Loading</> : <span>Start now</span>}
                </CustomButton>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </form>
    </Form>
  );
};
