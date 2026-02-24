"use client";

import { Divider } from "@heroui/divider";
import { ChevronLeftIcon, ChevronRightIcon, Loader2 } from "lucide-react";
import { useEffect } from "react";
import { Control, UseFormSetValue } from "react-hook-form";

import { Button } from "@/components/shadcn";
import { Form } from "@/components/ui/form";
import { useCredentialsForm } from "@/hooks/use-credentials-form";
import { getAWSCredentialsTemplateLinks } from "@/lib";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { requiresBackButton } from "@/lib/provider-helpers";
import {
  AlibabaCloudCredentials,
  AlibabaCloudCredentialsRole,
  ApiResponse,
  AWSCredentials,
  AWSCredentialsRole,
  AzureCredentials,
  CloudflareApiKeyCredentials,
  CloudflareTokenCredentials,
  GCPDefaultCredentials,
  GCPServiceAccountKey,
  IacCredentials,
  KubernetesCredentials,
  M365CertificateCredentials,
  M365ClientSecretCredentials,
  MongoDBAtlasCredentials,
  OCICredentials,
  OpenStackCredentials,
  ProviderType,
} from "@/types";

import { ProviderTitleDocs } from "../provider-title-docs";
import {
  AlibabaCloudRoleCredentialsForm,
  AlibabaCloudStaticCredentialsForm,
} from "./select-credentials-type/alibabacloud/credentials-type";
import { AWSStaticCredentialsForm } from "./select-credentials-type/aws/credentials-type";
import { AWSRoleCredentialsForm } from "./select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import {
  CloudflareApiKeyCredentialsForm,
  CloudflareApiTokenCredentialsForm,
} from "./select-credentials-type/cloudflare";
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
import { MongoDBAtlasCredentialsForm } from "./via-credentials/mongodbatlas-credentials-form";
import { OpenStackCredentialsForm } from "./via-credentials/openstack-credentials-form";
import { OracleCloudCredentialsForm } from "./via-credentials/oraclecloud-credentials-form";

type BaseCredentialsFormProps = {
  providerType: ProviderType;
  providerId: string;
  providerUid?: string;
  onSubmit: (formData: FormData) => Promise<ApiResponse>;
  successNavigationUrl: string;
  via?: string | null;
  onSuccess?: () => void;
  onBack?: () => void;
  formId?: string;
  hideActions?: boolean;
  onLoadingChange?: (isLoading: boolean) => void;
  onValidityChange?: (isValid: boolean) => void;
  submitButtonText?: string;
  showBackButton?: boolean;
  validationMode?: "onSubmit" | "onChange";
};

export const BaseCredentialsForm = ({
  providerType,
  providerId,
  providerUid,
  onSubmit,
  successNavigationUrl,
  via,
  onSuccess,
  onBack,
  formId,
  hideActions = false,
  onLoadingChange,
  onValidityChange,
  submitButtonText = "Next",
  showBackButton = true,
  validationMode,
}: BaseCredentialsFormProps) => {
  const {
    form,
    isLoading,
    isValid,
    handleSubmit,
    handleBackStep,
    effectiveVia,
    externalId,
  } = useCredentialsForm({
    providerType,
    providerId,
    providerUid,
    onSubmit,
    successNavigationUrl,
    via,
    onSuccess,
    onBack,
    validationMode,
  });

  useEffect(() => {
    onLoadingChange?.(isLoading);
  }, [isLoading, onLoadingChange]);

  useEffect(() => {
    onValidityChange?.(isValid);
  }, [isValid, onValidityChange]);

  const templateLinks = getAWSCredentialsTemplateLinks(externalId);

  return (
    <Form {...form}>
      <form
        id={formId}
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

        {providerType === "aws" && effectiveVia === "role" && (
          <AWSRoleCredentialsForm
            control={form.control as unknown as Control<AWSCredentialsRole>}
            setValue={
              form.setValue as unknown as UseFormSetValue<AWSCredentialsRole>
            }
            externalId={externalId}
            templateLinks={templateLinks}
          />
        )}
        {providerType === "aws" && effectiveVia !== "role" && (
          <AWSStaticCredentialsForm
            control={form.control as unknown as Control<AWSCredentials>}
          />
        )}
        {providerType === "azure" && (
          <AzureCredentialsForm
            control={form.control as unknown as Control<AzureCredentials>}
          />
        )}
        {providerType === "m365" && effectiveVia === "app_client_secret" && (
          <M365ClientSecretCredentialsForm
            control={
              form.control as unknown as Control<M365ClientSecretCredentials>
            }
          />
        )}
        {providerType === "m365" && effectiveVia === "app_certificate" && (
          <M365CertificateCredentialsForm
            control={
              form.control as unknown as Control<M365CertificateCredentials>
            }
          />
        )}
        {providerType === "gcp" && effectiveVia === "service-account" && (
          <GCPServiceAccountKeyForm
            control={form.control as unknown as Control<GCPServiceAccountKey>}
          />
        )}
        {providerType === "gcp" && effectiveVia !== "service-account" && (
          <GCPDefaultCredentialsForm
            control={form.control as unknown as Control<GCPDefaultCredentials>}
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
            credentialsType={effectiveVia || undefined}
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
        {providerType === "mongodbatlas" && (
          <MongoDBAtlasCredentialsForm
            control={
              form.control as unknown as Control<MongoDBAtlasCredentials>
            }
          />
        )}
        {providerType === "alibabacloud" && effectiveVia === "role" && (
          <AlibabaCloudRoleCredentialsForm
            control={
              form.control as unknown as Control<AlibabaCloudCredentialsRole>
            }
          />
        )}
        {providerType === "alibabacloud" && effectiveVia !== "role" && (
          <AlibabaCloudStaticCredentialsForm
            control={
              form.control as unknown as Control<AlibabaCloudCredentials>
            }
          />
        )}
        {providerType === "cloudflare" && effectiveVia === "api_token" && (
          <CloudflareApiTokenCredentialsForm
            control={
              form.control as unknown as Control<CloudflareTokenCredentials>
            }
          />
        )}
        {providerType === "cloudflare" && effectiveVia === "api_key" && (
          <CloudflareApiKeyCredentialsForm
            control={
              form.control as unknown as Control<CloudflareApiKeyCredentials>
            }
          />
        )}
        {providerType === "openstack" && (
          <OpenStackCredentialsForm
            control={form.control as unknown as Control<OpenStackCredentials>}
          />
        )}

        {!hideActions && (
          <div className="flex w-full justify-end gap-4">
            {showBackButton && requiresBackButton(effectiveVia) && (
              <Button
                type="button"
                variant="ghost"
                size="lg"
                onClick={handleBackStep}
                disabled={isLoading}
              >
                {!isLoading && <ChevronLeftIcon size={24} />}
                Back
              </Button>
            )}
            <Button
              type="submit"
              variant="default"
              size="lg"
              disabled={isLoading}
            >
              {isLoading ? (
                <Loader2 className="animate-spin" />
              ) : (
                <ChevronRightIcon size={24} />
              )}
              {isLoading ? "Loading" : submitButtonText}
            </Button>
          </div>
        )}
      </form>
    </Form>
  );
};
