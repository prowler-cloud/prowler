"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Icon } from "@iconify/react";
import { Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  checkConnectionProvider,
  deleteCredentials,
} from "@/actions/providers";
import { getTask } from "@/actions/task/tasks";
import { CheckIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/ui";
import { Form } from "@/components/ui/form";
import { checkTaskStatus } from "@/lib/helper";
import { ProviderType } from "@/types";
import { ApiError, testConnectionFormSchema } from "@/types";

import { ProviderInfo } from "../..";

type FormValues = z.input<typeof testConnectionFormSchema>;

export interface TestConnectionProviderData {
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
      scanner_args: Record<string, unknown>;
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
}

interface TestConnectionFormProps {
  searchParams: { type: string; id: string; updated: string };
  providerData: TestConnectionProviderData;
  onSuccess?: () => void;
  onResetCredentials?: () => void;
  formId?: string;
  hideActions?: boolean;
  onLoadingChange?: (isLoading: boolean) => void;
}

export const TestConnectionForm = ({
  searchParams,
  providerData,
  onSuccess,
  onResetCredentials: onResetCredentialsCallback,
  formId,
  hideActions = false,
  onLoadingChange,
}: TestConnectionFormProps) => {
  const { toast } = useToast();
  const router = useRouter();

  const providerId = searchParams.id;

  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    error: string | null;
  } | null>(null);
  const [isResettingCredentials, setIsResettingCredentials] = useState(false);

  const formSchema = testConnectionFormSchema;

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
    },
  });

  const isLoading = form.formState.isSubmitting;
  const isUpdated = searchParams?.updated === "true";

  useEffect(() => {
    onLoadingChange?.(isLoading || isResettingCredentials);
  }, [isLoading, isResettingCredentials, onLoadingChange]);

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

        if (connected && isUpdated) {
          if (onSuccess) {
            onSuccess();
            return;
          }
          return router.push("/providers");
        }

        if (connected && !isUpdated) {
          if (onSuccess) {
            onSuccess();
            return;
          }

          return router.push("/providers");
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

  const handleResetCredentials = async () => {
    setIsResettingCredentials(true);

    // Check if provider the provider has no credentials
    const providerSecretId =
      providerData?.data?.relationships?.secret?.data?.id;
    const hasNoCredentials = !providerSecretId;

    if (hasNoCredentials) {
      if (onResetCredentialsCallback) {
        onResetCredentialsCallback();
      } else {
        router.push("/providers");
      }
      setIsResettingCredentials(false);
      return;
    }

    // If provider has credentials, delete them first
    try {
      await deleteCredentials(providerSecretId);
      if (onResetCredentialsCallback) {
        onResetCredentialsCallback();
      } else {
        router.push("/providers");
      }
    } catch (error) {
      console.error("Failed to delete credentials:", error);
    } finally {
      setIsResettingCredentials(false);
    }
  };

  return (
    <Form {...form}>
      <form
        id={formId}
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col gap-4"
      >
        <div className="text-left">
          <div className="mb-2 text-xl font-medium">Check connection</div>
          <p className="text-small text-default-500 py-2">
            {!isUpdated
              ? "After a successful connection, continue to the launch step to configure and start your scan."
              : "A successful connection will redirect you to the providers page."}
          </p>
        </div>

        {apiErrorMessage && (
          <div className="text-text-error-primary mt-4 rounded-md">
            <p>{apiErrorMessage}</p>
          </div>
        )}

        {connectionStatus && !connectionStatus.connected && (
          <>
            <div className="border-border-error flex items-start gap-4 rounded-lg border p-4">
              <div className="flex shrink-0 items-center">
                <Icon
                  icon="heroicons:exclamation-circle"
                  className="text-text-error-primary h-5 w-5"
                />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-small text-text-error-primary break-words">
                  {connectionStatus.error || "Unknown error"}
                </p>
              </div>
            </div>
            <p className="text-small text-text-error-primary">
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

        {isUpdated && !connectionStatus?.error && (
          <p className="text-small text-default-500 py-2">
            Check the new credentials and test the connection.
          </p>
        )}

        <input type="hidden" name="providerId" value={providerId} />

        {!hideActions && (
          <div className="flex w-full justify-end sm:gap-6">
            {apiErrorMessage ? (
              <Button variant="outline" size="lg" asChild>
                <Link href="/providers">Back to providers</Link>
              </Button>
            ) : connectionStatus?.error ? (
              <Button
                onClick={
                  isUpdated
                    ? onResetCredentialsCallback || (() => router.back())
                    : handleResetCredentials
                }
                type="button"
                variant="secondary"
                size="lg"
                disabled={isResettingCredentials}
              >
                {isResettingCredentials ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <CheckIcon size={24} />
                )}
                {isResettingCredentials
                  ? "Loading"
                  : isUpdated
                    ? "Update credentials"
                    : "Reset credentials"}
              </Button>
            ) : (
              <Button
                type={
                  isUpdated && connectionStatus?.connected ? "button" : "submit"
                }
                variant="default"
                size="lg"
                disabled={isLoading}
              >
                {isLoading ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <CheckIcon size={24} />
                )}
                {isLoading
                  ? "Checking"
                  : isUpdated
                    ? "Check connection"
                    : "Continue"}
              </Button>
            )}
          </div>
        )}
      </form>
    </Form>
  );
};
