"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { RocketIcon, ScheduleIcon } from "@/components/icons";
// import { useToast } from "@/components/ui";
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

  //   const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);

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

  const isLoading = form.formState.isSubmitting;

  const isConnected = providerData.data.attributes.connection.connected;

  const onSubmitClient = async (values: FormValues) => {
    console.log({ values }, "values from test connection form");

    if (isConnected) {
      console.log("connected");
    } else {
      console.log("not connected");
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
            Launch scan
          </div>
          <div className="py-2 text-default-500">
            Launch the scan now or schedule it for a later date and time.
          </div>
        </div>

        {/* {apiErrorMessage && (
          <div className="mt-4 rounded-md bg-red-100 p-3 text-red-700">
            <p>{`Provider ID ${apiErrorMessage.toLowerCase()}. Please check and try again.`}</p>
          </div>
        )} */}

        <ProviderInfo
          connected={providerData.data.attributes.connection.connected}
          provider={providerData.data.attributes.provider}
          providerAlias={providerData.data.attributes.alias}
        />

        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        <div className="flex w-full justify-end sm:space-x-6">
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
        </div>
      </form>
    </Form>
  );
};
