"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Divider } from "@nextui-org/divider";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Control, useForm } from "react-hook-form";
import * as z from "zod";

import { addCredentialsProvider } from "@/actions/providers/providers";
import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { useFormServerErrors } from "@/hooks/use-form-server-errors";
import { PROVIDER_CREDENTIALS_ERROR_MAPPING } from "@/lib/error-mappings";
import {
  addCredentialsFormSchema,
  AWSCredentials,
  AzureCredentials,
  GCPDefaultCredentials,
  KubernetesCredentials,
  M365Credentials,
  ProviderType,
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
  GCPDefaultCredentials &
  KubernetesCredentials &
  M365Credentials;

export const ViaCredentialsForm = ({
  searchParams,
}: {
  searchParams: { type: string; id: string };
}) => {
  const router = useRouter();
  const searchParamsObj = useSearchParams();

  // Handler for back button
  const handleBackStep = () => {
    const currentParams = new URLSearchParams(window.location.search);
    currentParams.delete("via");
    router.push(`?${currentParams.toString()}`);
  };

  const providerType = searchParams.type as ProviderType;
  const providerId = searchParams.id;
  const formSchema = addCredentialsFormSchema(providerType);

  const formSetCredentials = useForm<FormType>({
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

  const isLoading = formSetCredentials.formState.isSubmitting;
  const { handleServerResponse } = useFormServerErrors(
    formSetCredentials,
    PROVIDER_CREDENTIALS_ERROR_MAPPING,
  );

  const onSubmitClient = async (values: FormType) => {
    const formData = new FormData();

    Object.entries(values).forEach(
      ([key, value]) => value !== undefined && formData.append(key, value),
    );

    const data = await addCredentialsProvider(formData);

    const isSuccess = handleServerResponse(data);
    if (isSuccess) {
      router.push(
        `/providers/test-connection?type=${providerType}&id=${providerId}`,
      );
    }
  };

  return (
    <Form {...formSetCredentials}>
      <form
        onSubmit={formSetCredentials.handleSubmit(onSubmitClient)}
        className="flex flex-col space-y-4"
      >
        <input type="hidden" name="providerId" value={providerId} />
        <input type="hidden" name="providerType" value={providerType} />

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {providerType === "aws" && (
          <AWSStaticCredentialsForm
            control={
              formSetCredentials.control as unknown as Control<AWSCredentials>
            }
          />
        )}
        {providerType === "azure" && (
          <AzureCredentialsForm
            control={
              formSetCredentials.control as unknown as Control<AzureCredentials>
            }
          />
        )}
        {providerType === "m365" && (
          <M365CredentialsForm
            control={
              formSetCredentials.control as unknown as Control<M365Credentials>
            }
          />
        )}
        {providerType === "gcp" && (
          <GCPDefaultCredentialsForm
            control={
              formSetCredentials.control as unknown as Control<GCPDefaultCredentials>
            }
          />
        )}
        {providerType === "kubernetes" && (
          <KubernetesCredentialsForm
            control={
              formSetCredentials.control as unknown as Control<KubernetesCredentials>
            }
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
