"use client";

import { Divider } from "@heroui/divider";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { Control } from "react-hook-form";

import { CustomButton } from "@/components/ui/custom";
import { Form } from "@/components/ui/form";
import { useCredentialsForm } from "@/hooks/use-credentials-form";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { requiresBackButton } from "@/lib/provider-helpers";
import {
  AWSCredentials,
  AWSCredentialsRole,
  AzureCredentials,
  GCPDefaultCredentials,
  GCPServiceAccountKey,
  IacCredentials,
  KubernetesCredentials,
  M365CertificateCredentials,
  M365ClientSecretCredentials,
  OCICredentials,
  ProviderType,
} from "@/types";

import { ProviderTitleDocs } from "../provider-title-docs";
import { AWSStaticCredentialsForm } from "./select-credentials-type/aws/credentials-type";
import { AWSRoleCredentialsForm } from "./select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { GCPDefaultCredentialsForm } from "./select-credentials-type/gcp/credentials-type";
import { GCPServiceAccountKeyForm } from "./select-credentials-type/gcp/credentials-type/gcp-service-account-key-form";
import {
  M365CertificateCredentialsForm,
  M365ClientSecretCredentialsForm,
} from "./select-credentials-type/m365";
import { AzureCredentialsForm } from "./via-credentials/azure-credentials-form";
import { GitHubCredentialsForm } from "./via-credentials/github-credentials-form";
import { IacCredentialsForm } from "./via-credentials/iac-credentials-form";
import { KubernetesCredentialsForm } from "./via-credentials/k8s-credentials-form";
import { OracleCloudCredentialsForm } from "./via-credentials/oraclecloud-credentials-form";

type BaseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  providerUid?: string;
  onSubmit: (formData: FormData) => Promise<any>;
  successNavigationUrl: string;
  submitButtonText?: string;
  showBackButton?: boolean;
};

export const BaseCredentialsForm = ({
  providerType,
  providerId,
  providerUid,
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
    providerUid,
    onSubmit,
    successNavigationUrl,
  });

  const templateLinks = getAWSCredentialsTemplateLinks(externalId);

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="flex flex-col gap-4"
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
        {providerUid && (
          <input
            type="hidden"
            name={ProviderCredentialFields.PROVIDER_UID}
            value={providerUid}
          />
        )}

        <ProviderTitleDocs providerType={providerType} />

        <Divider />

        {providerType === "aws" && searchParamsObj.get("via") === "role" && (
          <AWSRoleCredentialsForm
            control={form.control as unknown as Control<AWSCredentialsRole>}
            setValue={form.setValue as any}
            externalId={externalId}
            templateLinks={templateLinks}
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
        {providerType === "m365" &&
          searchParamsObj.get("via") === "app_client_secret" && (
            <M365ClientSecretCredentialsForm
              control={
                form.control as unknown as Control<M365ClientSecretCredentials>
              }
            />
          )}
        {providerType === "m365" &&
          searchParamsObj.get("via") === "app_certificate" && (
            <M365CertificateCredentialsForm
              control={
                form.control as unknown as Control<M365CertificateCredentials>
              }
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
        {providerType === "github" && (
          <GitHubCredentialsForm
            control={form.control}
            credentialsType={searchParamsObj.get("via") || undefined}
          />
        )}
        {providerType === "iac" && (
          <IacCredentialsForm
            control={form.control as unknown as Control<IacCredentials>}
          />
        )}
        {providerType === "oraclecloud" && (
          <OracleCloudCredentialsForm
            control={form.control as unknown as Control<OCICredentials>}
          />
        )}

        <div className="flex w-full justify-end sm:gap-6">
          {showBackButton && requiresBackButton(searchParamsObj.get("via")) && (
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
            onPress={(e) => {
              const formElement = e.target as HTMLElement;
              const form = formElement.closest("form");
              if (form) {
                form.dispatchEvent(
                  new Event("submit", { bubbles: true, cancelable: true }),
                );
              }
            }}
          >
            {isLoading ? <>Loading</> : <span>{submitButtonText}</span>}
          </CustomButton>
        </div>
      </form>
    </Form>
  );
};
