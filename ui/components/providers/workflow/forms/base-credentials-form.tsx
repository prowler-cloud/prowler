"use client";

import { Divider } from "@nextui-org/react";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { Control } from "react-hook-form";

import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { useCredentialsForm } from "@/hooks/use-credentials-form";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import {
  AWSCredentials,
  AWSCredentialsRole,
  AzureCredentials,
  GCPDefaultCredentials,
  GCPServiceAccountKey,
  KubernetesCredentials,
  M365Credentials,
  ProviderType,
} from "@/types";

import { ProviderTitleDocs } from "../provider-title-docs";
import { AWSStaticCredentialsForm } from "./select-credentials-type/aws/credentials-type";
import { AWSRoleCredentialsForm } from "./select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { GCPDefaultCredentialsForm } from "./select-credentials-type/gcp/credentials-type";
import { GCPServiceAccountKeyForm } from "./select-credentials-type/gcp/credentials-type/gcp-service-account-key-form";
import { AzureCredentialsForm } from "./via-credentials/azure-credentials-form";
import { KubernetesCredentialsForm } from "./via-credentials/k8s-credentials-form";
import { M365CredentialsForm } from "./via-credentials/m365-credentials-form";

type BaseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  onSubmit: (formData: FormData) => Promise<any>;
  successNavigationUrl: string;
  submitButtonText?: string;
  showBackButton?: boolean;
};

export const BaseCredentialsForm = ({
  providerType,
  providerId,
  onSubmit,
  successNavigationUrl,
  submitButtonText = "Next",
  showBackButton = true,
}: BaseCredentialsFormProps) => {
  const {
    form,
    isLoading,
    handleSubmit,
    handleBackStep,
    searchParamsObj,
    externalId,
  } = useCredentialsForm({
    providerType,
    providerId,
    onSubmit,
    successNavigationUrl,
  });

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="flex flex-col space-y-4"
      >
        <input
          type="hidden"
          name={ProviderCredentialFields.PROVIDER_ID}
          value={providerId}
        />
        <input
          type="hidden"
          name={ProviderCredentialFields.PROVIDER_TYPE}
          value={providerType}
        />

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {providerType === "aws" && searchParamsObj.get("via") === "role" && (
          <AWSRoleCredentialsForm
            control={form.control as unknown as Control<AWSCredentialsRole>}
            setValue={form.setValue as any}
            externalId={externalId}
          />
        )}
        {providerType === "aws" && searchParamsObj.get("via") !== "role" && (
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
        {providerType === "gcp" &&
          searchParamsObj.get("via") === "service-account" && (
            <GCPServiceAccountKeyForm
              control={form.control as unknown as Control<GCPServiceAccountKey>}
            />
          )}
        {providerType === "gcp" &&
          searchParamsObj.get("via") !== "service-account" && (
            <GCPDefaultCredentialsForm
              control={
                form.control as unknown as Control<GCPDefaultCredentials>
              }
            />
          )}
        {providerType === "kubernetes" && (
          <KubernetesCredentialsForm
            control={form.control as unknown as Control<KubernetesCredentials>}
          />
        )}

        <div className="flex w-full justify-end sm:space-x-6">
          {showBackButton &&
            (searchParamsObj.get("via") === "credentials" ||
              searchParamsObj.get("via") === "role" ||
              searchParamsObj.get("via") === "service-account") && (
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
            ariaLabel="Save"
            className="w-1/2"
            variant="solid"
            color="action"
            size="lg"
            isLoading={isLoading}
            endContent={!isLoading && <ChevronRightIcon size={24} />}
          >
            {isLoading ? <>Loading</> : <span>{submitButtonText}</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
