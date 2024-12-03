"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { scanOnDemand } from "@/actions/scans/scans";
import { AddIcon } from "@/components/icons";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ProviderProps } from "@/types"; // Asegúrate de importar la interfaz correcta
import { launchScanFormSchema } from "@/types/formSchemas";

import { ProviderInfo } from "../../provider-info";

type FormValues = z.infer<ReturnType<typeof launchScanFormSchema>>;

interface LaunchScanFormProps {
  searchParams: { type: string; id: string };
  providerData: {
    data: {
      type: string;
      id: string;
      attributes: ProviderProps["attributes"];
    };
  };
}

export const LaunchScanForm = ({
  searchParams,
  providerData,
}: LaunchScanFormProps) => {
  const providerType = searchParams.type;
  const providerId = searchParams.id;

  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);
  const router = useRouter();

  const formSchema = launchScanFormSchema();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      scannerArgs: {
        checksToExecute: [],
      },
    },
  });

  // const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    const formData = new FormData();
    formData.append("providerId", values.providerId);

    // Generate default scan name using provider type and current date
    const date = new Date();
    const month = (date.getMonth() + 1).toString().padStart(2, "0");
    const day = date.getDate().toString().padStart(2, "0");
    const year = date.getFullYear();
    const defaultScanName = `${providerType}:${month}/${day}/${year}`;

    formData.append("scanName", defaultScanName);

    try {
      const data = await scanOnDemand(formData);

      if (data.error) {
        setApiErrorMessage(data.error);
        form.setError("providerId", {
          type: "server",
          message: data.error,
        });
      } else {
        router.push("/scans");
      }
    } catch (error) {
      form.setError("providerId", {
        type: "server",
        message: "An unexpected error occurred. Please try again.",
      });
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="text-left">
          <div className="text-2xl font-bold leading-9 text-default-foreground">
            Scan started
          </div>
          <div className="py-2 text-default-500">
            The scan has just started. From now on, a new scan will be launched
            every 24 hours, starting from this moment.
          </div>
        </div>

        {apiErrorMessage && (
          <div className="mt-4 rounded-md bg-red-100 p-3 text-red-700">
            <p>{apiErrorMessage.toLowerCase()}</p>
          </div>
        )}

        <ProviderInfo
          connected={providerData.data.attributes.connection.connected}
          provider={providerData.data.attributes.provider}
          providerAlias={providerData.data.attributes.alias}
        />

        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        {/* <div className="flex w-full justify-end sm:space-x-6">
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            startContent={!isLoading && <ScheduleIcon size={24} />}
            isDisabled={true}
          >
            <span>Schedule</span>
          </CustomButton>
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <RocketIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Start now</span>}
          </CustomButton>
        </div> */}
        <div className="flex w-full items-center justify-end">
          <CustomButton
            asLink="/scans"
            ariaLabel="Go to Scans page"
            variant="solid"
            color="action"
            size="md"
            endContent={<AddIcon size={20} />}
          >
            Go to Scans
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
