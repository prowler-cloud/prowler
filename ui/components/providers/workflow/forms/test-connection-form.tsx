"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { Checkbox } from "@nextui-org/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  checkConnectionProvider,
  deleteCredentials,
} from "@/actions/providers";
import { scanOnDemand, scheduleDaily } from "@/actions/scans";
import { getTask } from "@/actions/task/tasks";
import { CheckIcon, RocketIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { checkTaskStatus } from "@/lib/helper";
import { ApiError, testConnectionFormSchema } from "@/types";

import { ProviderInfo } from "../..";
import { ProviderType } from "@/components/ui/entities";

type FormValues = z.infer<typeof testConnectionFormSchema>;

export const TestConnectionForm = ({
  searchParams,
  providerData,
}: {
  searchParams: { type: string; id: string; updated: string };
  providerData: {
    data: {
      id: string;
      type: string;
      attributes: {
        uid: string;
        connection: {
          connected: boolean | null;
          last_checked_at: string | null;
        };
        provider: ProviderType;
        alias: string;
        scanner_args: Record<string, any>;
      };
      relationships: {
        secret: {
          data: {
            type: string;
            id: string;
          } | null;
        };
      };
    };
  };
}) => {
  const { toast } = useToast();
  const router = useRouter();

  const providerType = searchParams.type;
  const providerId = searchParams.id;

  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    error: string | null;
  } | null>(null);
  const [isResettingCredentials, setIsResettingCredentials] = useState(false);
  const [isRedirecting, setIsRedirecting] = useState(false);

  const formSchema = testConnectionFormSchema;

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      runOnce: false,
    },
  });

  const isLoading = form.formState.isSubmitting;
  const isUpdated = searchParams?.updated === "true";

  const onSubmitClient = async (values: FormValues) => {
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
        const task = await getTask(taskId);
        const { connected, error } = task.data.attributes.result;

        setConnectionStatus({
          connected,
          error: connected ? null : error || "Unknown error",
        });

        if (connected && isUpdated) return router.push("/providers");

        if (connected && !isUpdated) {
          try {
            // Check if the runOnce checkbox is checked
            const runOnce = form.watch("runOnce");

            let data;

            if (runOnce) {
              data = await scanOnDemand(formData);
            } else {
              data = await scheduleDaily(formData);
            }

            if (data.error) {
              setApiErrorMessage(data.error);
              form.setError("providerId", {
                type: "server",
                message: data.error,
              });
            } else {
              setIsRedirecting(true);
              router.push("/scans");
            }
          } catch (error) {
            form.setError("providerId", {
              type: "server",
              message: "An unexpected error occurred. Please try again.",
            });
          }
        } else {
          setConnectionStatus({
            connected: false,
            error: error || "Connection failed, please review credentials.",
          });
        }
      } else {
        setConnectionStatus({
          connected: false,
          error: taskResult.error || "Unknown error",
        });
      }
    }
  };

  const onResetCredentials = async () => {
    setIsResettingCredentials(true);

    // Check if provider the provider has no credentials
    const providerSecretId =
      providerData?.data?.relationships?.secret?.data?.id;
    const hasNoCredentials = !providerSecretId;

    if (hasNoCredentials) {
      // If no credentials, redirect to add credentials page
      router.push(
        `/providers/add-credentials?type=${providerType}&id=${providerId}`,
      );
      return;
    }

    // If provider has credentials, delete them first
    try {
      await deleteCredentials(providerSecretId);
      // After successful deletion, redirect to add credentials page
      router.push(
        `/providers/add-credentials?type=${providerType}&id=${providerId}`,
      );
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("Failed to delete credentials:", error);
    } finally {
      setIsResettingCredentials(false);
    }
  };

  if (isRedirecting) {
    return (
      <div className="flex flex-col items-center justify-center space-y-6 py-12">
        <div className="relative">
          <div className="h-24 w-24 animate-pulse rounded-full bg-primary/20" />
          <div className="absolute inset-0 h-24 w-24 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        </div>
        <div className="text-center">
          <p className="text-xl font-medium text-primary">
            Scan initiated successfully
          </p>
          <p className="mt-2 text-small font-bold text-gray-500">
            Redirecting to scans job details...
          </p>
        </div>
      </div>
    );
  }

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <div className="text-left">
          <div className="mb-2 text-xl font-medium">
            {!isUpdated
              ? "Check connection and launch scan"
              : "Check connection"}
          </div>
          <p className="py-2 text-small text-default-500">
            {!isUpdated
              ? "After a successful connection, a scan will automatically run every 24 hours. To run a single scan instead, select the checkbox below."
              : "A successful connection will redirect you to the providers page."}
          </p>
        </div>

        {apiErrorMessage && (
          <div className="mt-4 rounded-md bg-red-100 p-3 text-danger">
            <p>{`Provider ID ${apiErrorMessage?.toLowerCase()}. Please check and try again.`}</p>
          </div>
        )}

        {connectionStatus && !connectionStatus.connected && (
          <>
            <div className="flex items-center gap-4 rounded-lg border border-red-200 bg-red-50 p-4">
              <div className="flex items-center">
                <Icon
                  icon="heroicons:exclamation-circle"
                  className="h-5 w-5 text-danger"
                />
              </div>
              <div className="flex items-center">
                <p className="text-small text-danger">
                  {connectionStatus.error || "Unknown error"}
                </p>
              </div>
            </div>
            <p className="text-small text-danger">
              It seems there was an issue with your credentials. Please review
              your credentials and try again.
            </p>
          </>
        )}

        <ProviderInfo
          connected={providerData.data.attributes.connection.connected}
          provider={providerData.data.attributes.provider}
          providerAlias={providerData.data.attributes.alias}
          providerUID={providerData.data.attributes.uid}
        />

        {!isUpdated && !connectionStatus?.error && (
          <Checkbox
            {...form.register("runOnce")}
            isSelected={!!form.watch("runOnce")}
            classNames={{
              label: "text-small text-default-500",
              wrapper: "checkbox-update",
            }}
          >
            Run a single scan (no recurring schedule).
          </Checkbox>
        )}

        {isUpdated && !connectionStatus?.error && (
          <p className="py-2 text-small text-default-500">
            Check the new credentials and test the connection.
          </p>
        )}

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
            <CustomButton
              onPress={isUpdated ? () => router.back() : onResetCredentials}
              type="button"
              ariaLabel={"Save"}
              className="w-1/2"
              variant="solid"
              color="warning"
              size="md"
              isLoading={isResettingCredentials}
              startContent={!isResettingCredentials && <CheckIcon size={24} />}
              isDisabled={isResettingCredentials}
            >
              {isResettingCredentials ? (
                <>Loading</>
              ) : (
                <span>
                  {isUpdated ? "Update credentials" : "Reset credentials"}
                </span>
              )}
            </CustomButton>
          ) : (
            <CustomButton
              type={
                isUpdated && connectionStatus?.connected ? "button" : "submit"
              }
              ariaLabel={"Save"}
              className="w-1/3"
              variant="solid"
              color="action"
              size="md"
              isLoading={isLoading}
              endContent={!isLoading && !isUpdated && <RocketIcon size={24} />}
            >
              {isLoading ? (
                <>Loading</>
              ) : (
                <span>{isUpdated ? "Check connection" : "Launch scan"}</span>
              )}
            </CustomButton>
          )}
        </div>
      </form>
    </Form>
  );
};
