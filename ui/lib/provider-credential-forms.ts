"use client";

import { AWSStaticCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type";
import { AWSRoleCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/aws/credentials-type/aws-role-credentials-form";
import { GCPDefaultCredentialsForm } from "@/components/providers/workflow/forms/select-credentials-type/gcp/credentials-type";
import { GCPServiceAccountKeyForm } from "@/components/providers/workflow/forms/select-credentials-type/gcp/credentials-type/gcp-service-account-key-form";
import {
  M365CertificateCredentialsForm,
  M365ClientSecretCredentialsForm,
} from "@/components/providers/workflow/forms/select-credentials-type/m365";
import { AzureCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/azure-credentials-form";
import { GitHubCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/github-credentials-form";
import { KubernetesCredentialsForm } from "@/components/providers/workflow/forms/via-credentials/k8s-credentials-form";
import { ProviderType } from "@/types/providers";

// Type definitions for different credential form configurations
export type CredentialFormConfigExtended = {
  component: typeof AWSRoleCredentialsForm;
  requiresExtendedProps: true;
  passesCredentialsType: false;
};

export type CredentialFormConfigPassesCredentialsType = {
  component: typeof GitHubCredentialsForm;
  requiresExtendedProps: false;
  passesCredentialsType: true;
};

export type CredentialFormConfigBasic = {
  component:
    | typeof AWSStaticCredentialsForm
    | typeof GCPServiceAccountKeyForm
    | typeof GCPDefaultCredentialsForm
    | typeof M365ClientSecretCredentialsForm
    | typeof M365CertificateCredentialsForm
    | typeof AzureCredentialsForm
    | typeof KubernetesCredentialsForm;
  requiresExtendedProps: false;
  passesCredentialsType: false;
};

export type CredentialFormConfig =
  | CredentialFormConfigExtended
  | CredentialFormConfigPassesCredentialsType
  | CredentialFormConfigBasic;

// Provider credential form components mapping
const PROVIDER_CREDENTIAL_FORMS = {
  aws: {
    role: AWSRoleCredentialsForm,
    credentials: AWSStaticCredentialsForm,
  },
  gcp: {
    "service-account": GCPServiceAccountKeyForm,
    credentials: GCPDefaultCredentialsForm,
  },
  m365: {
    app_client_secret: M365ClientSecretCredentialsForm,
    app_certificate: M365CertificateCredentialsForm,
  },
  azure: {
    default: AzureCredentialsForm,
  },
  kubernetes: {
    default: KubernetesCredentialsForm,
  },
  github: {
    default: GitHubCredentialsForm,
  },
} as const;

// Strategy dictionary: maps (provider + via) to credential form config
type ProviderViaKey =
  | "aws:role"
  | "aws"
  | "gcp:service-account"
  | "gcp"
  | "m365:app_client_secret"
  | "m365:app_certificate"
  | "github"
  | "azure"
  | "kubernetes";

const PROVIDER_VIA_STRATEGIES = {
  // AWS strategies
  "aws:role": () => ({
    component: PROVIDER_CREDENTIAL_FORMS.aws.role,
    requiresExtendedProps: true,
    passesCredentialsType: false,
  }),
  aws: () => ({
    component: PROVIDER_CREDENTIAL_FORMS.aws.credentials,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),

  // GCP strategies
  "gcp:service-account": () => ({
    component: PROVIDER_CREDENTIAL_FORMS.gcp["service-account"],
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),
  gcp: () => ({
    component: PROVIDER_CREDENTIAL_FORMS.gcp.credentials,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),

  // M365 strategies
  "m365:app_client_secret": () => ({
    component: PROVIDER_CREDENTIAL_FORMS.m365.app_client_secret,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),
  "m365:app_certificate": () => ({
    component: PROVIDER_CREDENTIAL_FORMS.m365.app_certificate,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),

  // GitHub strategy
  github: () => ({
    component: PROVIDER_CREDENTIAL_FORMS.github.default,
    requiresExtendedProps: false,
    passesCredentialsType: true,
  }),

  // Azure strategy
  azure: () => ({
    component: PROVIDER_CREDENTIAL_FORMS.azure.default,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),

  // Kubernetes strategy
  kubernetes: () => ({
    component: PROVIDER_CREDENTIAL_FORMS.kubernetes.default,
    requiresExtendedProps: false,
    passesCredentialsType: false,
  }),
} satisfies Record<ProviderViaKey, () => CredentialFormConfig>;

// Helper to get credential form component based on provider and via parameter
export const getCredentialFormComponent = (
  provider: ProviderType,
  via?: string | null,
): CredentialFormConfig | null => {
  // Build strategy key: use "provider:via" if via exists, otherwise just "provider"
  const strategyKey = via ? `${provider}:${via}` : provider;

  const strategy = PROVIDER_VIA_STRATEGIES[strategyKey as ProviderViaKey];

  return strategy ? strategy() : null;
};
