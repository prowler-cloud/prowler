"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/react";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Control, useForm } from "react-hook-form";
import * as z from "zod";

import { updateCredentialsProvider } from "@/actions/providers/providers";
import { useToast } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { ProviderType } from "@/types";
import {
  addCredentialsFormSchema,
  ApiError,
  AWSCredentials,
  AzureCredentials,
  GCPDefaultCredentials,
  KubernetesCredentials,
  M365Credentials,
} from "@/types";

import { ProviderTitleDocs } from "../provider-title-docs";
import { AWSStaticCredentialsForm } from "./select-credentials-type/aws/credentials-type";
import { GCPDefaultCredentialsForm } from "./select-credentials-type/gcp/credentials-type";
import { AzureCredentialsForm } from "./via-credentials/azure-credentials-form";
import { KubernetesCredentialsForm } from "./via-credentials/k8s-credentials-form";
import { M365CredentialsForm } from "./via-credentials/m365-credentials-form";

type CredentialsFormSchema = z.infer<
  ReturnType<typeof addCredentialsFormSchema>
>;

// Add this type intersection to include all fields
type FormType = CredentialsFormSchema &
  AWSCredentials &
  AzureCredentials &
  M365Credentials &
  GCPDefaultCredentials &
  KubernetesCredentials;

export const UpdateViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string; secretId?: string };
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

  const providerType = searchParams.type as ProviderType;
  const providerId = searchParams.id;
  const providerSecretId = searchParams.secretId || "";
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
          : providerType === "m365"
            ? {
                client_id: "",
                client_secret: "",
                tenant_id: "",
                user: "",
                password: "",
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

  // Error pointer to field name mapping
  const errorPointerToFieldMap: Record<string, keyof FormType> = {
    "/data/attributes/secret/aws_access_key_id": "aws_access_key_id",
    "/data/attributes/secret/aws_secret_access_key": "aws_secret_access_key",
    "/data/attributes/secret/aws_session_token": "aws_session_token",
    "/data/attributes/secret/client_id": "client_id",
    "/data/attributes/secret/client_secret": "client_secret",
    "/data/attributes/secret/user": "user",
    "/data/attributes/secret/password": "password",
    "/data/attributes/secret/tenant_id": "tenant_id",
    "/data/attributes/secret/kubeconfig_content": "kubeconfig_content",
    "/data/attributes/name": "secretName",
  };

  const handleServerErrors = (errors: ApiError[]) => {
    errors.forEach((error: ApiError) => {
      const errorMessage = error.detail;
      const fieldName = errorPointerToFieldMap[error.source.pointer];

      if (fieldName) {
        form.setError(fieldName, {
          type: "server",
          message: errorMessage,
        });
      } else {
        // Handle unknown error pointers
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: errorMessage,
        });
      }
    });
  };

  const onSubmitClient = async (values: FormType) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await updateCredentialsProvider(providerSecretId, formData);

    // Handle single error from server
    if (data?.error) {
      return toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: data.error,
      });
    }

    // Handle multiple validation errors
    if (data?.errors?.length > 0) {
      return handleServerErrors(data.errors);
    }

    // Success: navigate to test connection page
    router.push(
      `/providers/test-connection?type=${providerType}&id=${providerId}&updated=true`,
    );
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {providerType === "aws" && (
          <AWSStaticCredentialsForm
            control={form.control as unknown as Control<AWSCredentials>}
          />
        )}
        {providerType === "azure" && (
          <AzureCredentialsForm
            control={form.control as unknown as Control<AzureCredentials>}
          />
        )}
        {providerType === "m365" && (
          <M365CredentialsForm
            control={form.control as unknown as Control<M365Credentials>}
          />
        )}
        {providerType === "gcp" && (
          <GCPDefaultCredentialsForm
            control={form.control as unknown as Control<GCPDefaultCredentials>}
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
