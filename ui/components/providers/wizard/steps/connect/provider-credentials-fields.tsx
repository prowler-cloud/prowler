"use client";

import { Control, FieldValues } from "react-hook-form";

import {
  AlibabaCloudRoleCredentialsForm,
  AlibabaCloudStaticCredentialsForm,
} from "@/components/providers/workflow/forms/select-credentials-type/alibabacloud/credentials-type";
import {
  CloudflareApiKeyCredentialsForm,
  CloudflareApiTokenCredentialsForm,
} from "@/components/providers/workflow/forms/select-credentials-type/cloudflare";
import { GCPDefaultCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/gcp/credentials-type";
import { GCPServiceAccountKeyForm } from "@/components/providers/workflow/forms/select-credentials-type/gcp/credentials-type/gcp-service-account-key-form";
import {
  M365CertificateCredentialsForm,
  M365ClientSecretCredentialsForm,
} from "@/components/providers/workflow/forms/select-credentials-type/m365";
import { AzureCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/azure-credentials-form";
import { GitHubCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/github-credentials-form";
import { GoogleWorkspaceCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/googleworkspace-credentials-form";
import { IacCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/iac-credentials-form";
import { ImageCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/image-credentials-form";
import { KubernetesCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/k8s-credentials-form";
import { MongoDBAtlasCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/mongodbatlas-credentials-form";
import { OktaCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/okta-credentials-form";
import { OpenStackCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/openstack-credentials-form";
import { OracleCloudCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/oraclecloud-credentials-form";
import { VercelCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/vercel-credentials-form";
import type {
  AlibabaCloudCredentials,
  AlibabaCloudCredentialsRole,
  AzureCredentials,
  CloudflareApiKeyCredentials,
  CloudflareTokenCredentials,
  GCPDefaultCredentials,
  GCPServiceAccountKey,
  GoogleWorkspaceCredentials,
  IacCredentials,
  ImageCredentials,
  KubernetesCredentials,
  KnownProviderType,
  M365CertificateCredentials,
  M365ClientSecretCredentials,
  MongoDBAtlasCredentials,
  OCICredentials,
  OktaCredentials,
  OpenStackCredentials,
  VercelCredentials,
} from "@/types";

interface ProviderCredentialsFieldsProps {
  providerType: KnownProviderType;
  via: string | null;
  control: Control<FieldValues>;
  /** The account id typed above, for providers whose help links need it. */
  providerUid?: string;
}

/** The credentials fields of a built-in provider (AWS has forms of its own). */
export function ProviderCredentialsFields({
  providerType,
  via,
  control,
  providerUid,
}: ProviderCredentialsFieldsProps) {
  return (
    <>
      {providerType === "azure" && (
        <AzureCredentialsForm
          control={control as unknown as Control<AzureCredentials>}
        />
      )}
      {providerType === "m365" && via === "app_client_secret" && (
        <M365ClientSecretCredentialsForm
          control={control as unknown as Control<M365ClientSecretCredentials>}
        />
      )}
      {providerType === "m365" && via === "app_certificate" && (
        <M365CertificateCredentialsForm
          control={control as unknown as Control<M365CertificateCredentials>}
        />
      )}
      {providerType === "gcp" && via === "service-account" && (
        <GCPServiceAccountKeyForm
          control={control as unknown as Control<GCPServiceAccountKey>}
        />
      )}
      {providerType === "gcp" && via !== "service-account" && (
        <GCPDefaultCredentialsForm
          control={control as unknown as Control<GCPDefaultCredentials>}
        />
      )}
      {providerType === "kubernetes" && (
        <KubernetesCredentialsForm
          control={control as unknown as Control<KubernetesCredentials>}
        />
      )}
      {providerType === "github" && (
        <GitHubCredentialsForm
          control={control}
          credentialsType={via || undefined}
          providerUid={providerUid}
        />
      )}
      {providerType === "iac" && (
        <IacCredentialsForm
          control={control as unknown as Control<IacCredentials>}
        />
      )}
      {providerType === "image" && (
        <ImageCredentialsForm
          control={control as unknown as Control<ImageCredentials>}
        />
      )}
      {providerType === "oraclecloud" && (
        <OracleCloudCredentialsForm
          control={control as unknown as Control<OCICredentials>}
        />
      )}
      {providerType === "mongodbatlas" && (
        <MongoDBAtlasCredentialsForm
          control={control as unknown as Control<MongoDBAtlasCredentials>}
        />
      )}
      {providerType === "alibabacloud" && via === "role" && (
        <AlibabaCloudRoleCredentialsForm
          control={control as unknown as Control<AlibabaCloudCredentialsRole>}
        />
      )}
      {providerType === "alibabacloud" && via !== "role" && (
        <AlibabaCloudStaticCredentialsForm
          control={control as unknown as Control<AlibabaCloudCredentials>}
        />
      )}
      {providerType === "cloudflare" && via === "api_token" && (
        <CloudflareApiTokenCredentialsForm
          control={control as unknown as Control<CloudflareTokenCredentials>}
          providerUid={providerUid}
        />
      )}
      {providerType === "cloudflare" && via === "api_key" && (
        <CloudflareApiKeyCredentialsForm
          control={control as unknown as Control<CloudflareApiKeyCredentials>}
        />
      )}
      {providerType === "openstack" && (
        <OpenStackCredentialsForm
          control={control as unknown as Control<OpenStackCredentials>}
        />
      )}
      {providerType === "googleworkspace" && (
        <GoogleWorkspaceCredentialsForm
          control={control as unknown as Control<GoogleWorkspaceCredentials>}
        />
      )}
      {providerType === "vercel" && (
        <VercelCredentialsForm
          control={control as unknown as Control<VercelCredentials>}
        />
      )}
      {providerType === "okta" && (
        <OktaCredentialsForm
          control={control as unknown as Control<OktaCredentials>}
        />
      )}
    </>
  );
}
