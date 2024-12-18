"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Control, useForm } from "react-hook-form";
import * as z from "zod";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { getProviderLogo } from "@/components/ui/entities";
import { getProviderName } from "@/components/ui/entities";
import { ProviderType } from "@/components/ui/entities";
import { Form } from "@/components/ui/form";
import {
  addCredentialsFormSchema,
  ApiError,
  AWSCredentials,
  AzureCredentials,
  GCPCredentials,
  KubernetesCredentials,
} from "@/types";

import { AWScredentialsForm } from "./via-credentials/aws-credentials-form";
import { AzureCredentialsForm } from "./via-credentials/azure-credentials-form";
import { GCPcredentialsForm } from "./via-credentials/gcp-credentials-form";
import { KubernetesCredentialsForm } from "./via-credentials/k8s-credentials-form";

type CredentialsFormSchema = z.infer<
  ReturnType<typeof addCredentialsFormSchema>
>;

// Add this type intersection to include all fields
type FormType = CredentialsFormSchema &
  AWSCredentials &
  AzureCredentials &
  GCPCredentials &
  KubernetesCredentials;

export const ViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string };
}) => {
  const router = useRouter();
  const { toast } = useToast();

  const searchParamsObj = useSearchParams();

  // Handler for back button
  const handleBackStep = () => {
    const currentParams = new URLSearchParams(window.location.search);
    currentParams.delete("via");
    router.push(`?${currentParams.toString()}`);
  };

  const providerType = searchParams.type;
  const providerId = searchParams.id;
  const formSchema = addCredentialsFormSchema(providerType);

  const form = useForm<FormType>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      providerId,
      providerType,
      ...(providerType === "aws"
        ? {
            aws_access_key_id: "",
            aws_secret_access_key: "",
            aws_session_token: "",
          }
        : providerType === "azure"
          ? {
              client_id: "",
              client_secret: "",
              tenant_id: "",
            }
          : providerType === "gcp"
            ? {
                client_id: "",
                client_secret: "",
                refresh_token: "",
              }
            : providerType === "kubernetes"
              ? {
                  kubeconfig_content: "",
                }
              : {}),
    },
  });

  const isLoading = form.formState.isSubmitting;

  const onSubmitClient = async (values: FormType) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addCredentialsProvider(formData);

    if (data?.errors && data.errors.length > 0) {
      data.errors.forEach((error: ApiError) => {
        const errorMessage = error.detail;
        switch (error.source.pointer) {
          case "/data/attributes/secret/aws_access_key_id":
            form.setError("aws_access_key_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/aws_secret_access_key":
            form.setError("aws_secret_access_key", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/aws_session_token":
            form.setError("aws_session_token", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/client_id":
            form.setError("client_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/client_secret":
            form.setError("client_secret", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/tenant_id":
            form.setError("tenant_id", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/secret/kubeconfig_content":
            form.setError("kubeconfig_content", {
              type: "server",
              message: errorMessage,
            });
            break;
          case "/data/attributes/name":
            form.setError("secretName", {
              type: "server",
              message: errorMessage,
            });
            break;
          default:
            toast({
              variant: "destructive",
              title: "Oops! Something went wrong",
              description: errorMessage,
            });
        }
      });
    } else {
      router.push(
        `/providers/test-connection?type=${providerType}&id=${providerId}`,
      );
    }
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        <div className="mb-4 flex items-center space-x-4">
          {providerType && getProviderLogo(providerType as ProviderType)}
          <span className="text-lg font-semibold">
            {providerType
              ? getProviderName(providerType as ProviderType)
              : "Unknown Provider"}
          </span>
        </div>

        {providerType === "aws" && (
          <AWScredentialsForm
            control={form.control as unknown as Control<AWSCredentials>}
          />
        )}
        {providerType === "azure" && (
          <AzureCredentialsForm
            control={form.control as unknown as Control<AzureCredentials>}
          />
        )}
        {providerType === "gcp" && (
          <GCPcredentialsForm
            control={form.control as unknown as Control<GCPCredentials>}
          />
        )}
        {providerType === "kubernetes" && (
          <KubernetesCredentialsForm
            control={form.control as unknown as Control<KubernetesCredentials>}
          />
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          {searchParamsObj.get("via") === "credentials" && (
            <CustomButton
              type="button"
              ariaLabel="Back"
              className="w-1/2 bg-transparent"
              variant="faded"
              size="lg"
              radius="lg"
              onPress={handleBackStep}
              startContent={!isLoading && <ChevronLeftIcon size={24} />}
              isDisabled={isLoading}
            >
              <span>Back</span>
            </CustomButton>
          )}
          <CustomButton
            type="submit"
            ariaLabel={"Save"}
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <ChevronRightIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>Next</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
