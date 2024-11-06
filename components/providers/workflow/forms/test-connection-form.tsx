"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { checkConnectionProvider } from "@/actions/providers/providers";
import { getTask } from "@/actions/task/tasks";
import { SaveIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { checkTaskStatus } from "@/lib/helper";
import { ApiError, testConnectionFormSchema } from "@/types";

import { ProviderInfo } from "../..";

type FormValues = z.infer<typeof testConnectionFormSchema>;

export const TestConnectionForm = ({
  searchParams,
  providerData,
}: {
  searchParams: { type: string; id: string };
  providerData: {
    data: {
      id: string;
      attributes: {
        connection: {
          connected: boolean;
        };
        provider: "aws" | "azure" | "gcp" | "kubernetes";
        alias: string;
      };
    };
  };
}) => {
  const { toast } = useToast();
  const router = useRouter();
  const providerType = searchParams.type;
  const providerId = searchParams.id;

  const formSchema = testConnectionFormSchema;
  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    error: string | null;
  } | null>(null);

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormValues) => {
    console.log({ values }, "values from test connection form");
    const formData = new FormData();
    formData.append("providerId", values.providerId);

    const data = await checkConnectionProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;

        switch (errorMessage) {
          case "Not found.":
            setApiErrorMessage(errorMessage);
            break;
          default:
            toast({
              variant: "destructive",
              title: `Error ${error.status}`,
              description: errorMessage,
            });
        }
      });
    } else {
      const taskId = data.data.id;
      setApiErrorMessage(null);

      // Use the helper function to check the task status
      const taskResult = await checkTaskStatus(taskId);

      if (taskResult.completed) {
        // If the task is completed, fetch the final task data
        const task = await getTask(taskId);
        const connected = task.data.attributes.result.connected;

        setConnectionStatus({
          connected,
          error: null,
        });

        if (connected) {
          router.push(
            `/providers/launch-scan?type=${providerType}&id=${providerId}`,
          );
        }
      } else {
        // If the task failed, display the error message
        setConnectionStatus({
          connected: false,
          error: taskResult.error || "Unknown error",
        });
      }
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
            Test connection
          </div>
          <p className="py-2 text-default-500">
            Ensure all required credentials and configurations are completed
            accurately. A successful connection will enable the option to
            initiate a scan in the following step.
          </p>
        </div>

        {apiErrorMessage && (
          <div className="mt-4 rounded-md bg-red-100 p-3 text-red-700">
            <p>{`Provider ID ${apiErrorMessage.toLowerCase()}. Please check and try again.`}</p>
          </div>
        )}

        {connectionStatus && !connectionStatus.connected && (
          <div className="flex items-center gap-4 rounded-lg border border-red-200 bg-red-50 p-4">
            <div className="flex items-center">
              <Icon
                icon="heroicons:exclamation-circle"
                className="h-5 w-5 text-red-500"
              />
            </div>
            <div className="flex items-center">
              <p className="text-red-700">
                {connectionStatus.error || "Unknown error"}
              </p>
            </div>
          </div>
        )}

        <ProviderInfo
          connected={providerData.data.attributes.connection.connected}
          provider={providerData.data.attributes.provider}
          providerAlias={providerData.data.attributes.alias}
        />

        <input type="hidden" name="providerId" value={providerId} />

        <div className="flex w-full justify-end sm:space-x-6">
          {apiErrorMessage ? (
            <Link
              href="/providers"
              className="mr-3 flex w-fit items-center justify-center space-x-2 rounded-lg border border-solid border-gray-200 px-4 py-2 hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              <Icon
                icon="icon-park-outline:close-small"
                className="h-5 w-5 text-gray-600 dark:text-gray-400"
              />
              <span>Back to providers</span>
            </Link>
          ) : connectionStatus?.error ? (
            <Link
              href="/providers/add-credentials"
              className="mr-3 flex w-fit items-center justify-center space-x-2 rounded-lg border border-solid border-gray-200 px-4 py-2 hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              <Icon
                icon="icon-park-outline:close-small"
                className="h-5 w-5 text-gray-600 dark:text-gray-400"
              />
              <span>Handle credentials</span>
            </Link>
          ) : (
            <CustomButton
              type="submit"
              ariaLabel={"Save"}
              className="w-1/2"
              variant="solid"
              color="action"
              size="lg"
              isLoading={isLoading}
              startContent={!isLoading && <SaveIcon size={24} />}
            >
              {isLoading ? <>Loading</> : <span>Test connection</span>}
            </CustomButton>
          )}
        </div>
      </form>
    </Form>
  );
};
