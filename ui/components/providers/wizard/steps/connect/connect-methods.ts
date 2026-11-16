import {
  Cloud,
  FileKey,
  FileText,
  KeyRound,
  type LucideIcon,
  ShieldCheck,
  Ticket,
} from "lucide-react";

import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import type { KnownProviderType } from "@/types/providers";

export interface ConnectMethod {
  /** The `via` the account is stored with; null for a provider with one method. */
  via: string | null;
  label: string;
  icon: LucideIcon;
  recommended?: boolean;
}

const single = (label: string, icon: LucideIcon): ConnectMethod[] => [
  { via: null, label, icon },
];

/** How each built-in provider can be connected, in the order the step lists them. */
const PROVIDER_CONNECT_METHODS = {
  aws: [
    { via: "role", label: "IAM Role", icon: ShieldCheck, recommended: true },
    { via: "credentials", label: "Static access keys", icon: KeyRound },
  ],
  azure: single("Service principal", ShieldCheck),
  gcp: [
    {
      via: "service-account",
      label: "Service account key",
      icon: FileKey,
      recommended: true,
    },
    {
      via: "credentials",
      label: "Application default credentials",
      icon: KeyRound,
    },
  ],
  kubernetes: single("Kubeconfig", FileText),
  m365: [
    {
      via: "app_certificate",
      label: "App certificate",
      icon: FileKey,
      recommended: true,
    },
    { via: "app_client_secret", label: "App client secret", icon: KeyRound },
  ],
  github: [
    {
      via: "personal_access_token",
      label: "Personal access token",
      icon: KeyRound,
    },
    { via: "oauth_app", label: "OAuth app token", icon: Ticket },
    { via: "github_app", label: "GitHub App", icon: ShieldCheck },
  ],
  googleworkspace: single("Service account", FileKey),
  iac: single("Repository access", KeyRound),
  image: single("Registry credentials", KeyRound),
  oraclecloud: single("API signing key", FileKey),
  mongodbatlas: single("API key", KeyRound),
  alibabacloud: [
    { via: "role", label: "RAM role", icon: ShieldCheck, recommended: true },
    { via: "credentials", label: "Static access keys", icon: KeyRound },
  ],
  cloudflare: [
    { via: "api_token", label: "API token", icon: KeyRound, recommended: true },
    { via: "api_key", label: "API key and email", icon: KeyRound },
  ],
  openstack: single("clouds.yaml", Cloud),
  vercel: single("API token", KeyRound),
  okta: single("API service app", ShieldCheck),
} as const satisfies Record<KnownProviderType, readonly ConnectMethod[]>;

/** Registry providers pick their method inside the dynamic form. */
const REGISTRY_METHODS: readonly ConnectMethod[] = single(
  "Credentials",
  KeyRound,
);

export function getConnectMethods(
  providerType: string,
): readonly ConnectMethod[] {
  return Object.hasOwn(PROVIDER_CONNECT_METHODS, providerType)
    ? PROVIDER_CONNECT_METHODS[providerType as KnownProviderType]
    : REGISTRY_METHODS;
}

/** The method a stored `via` maps to, else the first one listed. */
export function resolveConnectMethod(
  providerType: string,
  via: string | null | undefined,
): ConnectMethod {
  const methods = getConnectMethods(providerType);
  return methods.find((method) => method.via === via) ?? methods[0];
}

interface UidFieldDetails {
  label: string;
  placeholder: string;
  /** The footer action while adding: "Connect account", "Connect project", … */
  submitLabel: string;
}

const UID_FIELD_DETAILS = {
  aws: {
    label: "Account ID",
    placeholder: "e.g. 123456789012",
    submitLabel: "Connect account",
  },
  gcp: {
    label: "Project ID",
    placeholder: "e.g. my-gcp-project",
    submitLabel: "Connect project",
  },
  azure: {
    label: "Subscription ID",
    placeholder: "e.g. fc94207a-d396-4a14-a7fd-12ab34cd56ef",
    submitLabel: "Connect subscription",
  },
  kubernetes: {
    label: "Kubernetes Context",
    placeholder: "e.g. my-cluster-context",
    submitLabel: "Connect cluster",
  },
  m365: {
    label: "Domain ID",
    placeholder: "e.g. your-domain.onmicrosoft.com",
    submitLabel: "Connect tenant",
  },
  github: {
    label: "Username/Organization",
    placeholder: "e.g. username or organization-name",
    submitLabel: "Connect account",
  },
  iac: {
    label: "Repository URL",
    placeholder: "e.g. https://github.com/user/repo",
    submitLabel: "Connect repository",
  },
  image: {
    label: "Registry URL",
    placeholder: "e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com",
    submitLabel: "Connect registry",
  },
  oraclecloud: {
    label: "Tenancy OCID",
    placeholder: "e.g. ocid1.tenancy.oc1..aaaaaaa...",
    submitLabel: "Connect tenancy",
  },
  mongodbatlas: {
    label: "Organization ID",
    placeholder: "e.g. 5f43a8c4e1234567890abcde",
    submitLabel: "Connect organization",
  },
  alibabacloud: {
    label: "Account ID",
    placeholder: "e.g. 1234567890123456",
    submitLabel: "Connect account",
  },
  cloudflare: {
    label: "Account ID",
    placeholder: "e.g. a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    submitLabel: "Connect account",
  },
  openstack: {
    label: "Project ID",
    placeholder: "e.g. a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    submitLabel: "Connect project",
  },
  googleworkspace: {
    label: "Customer ID",
    placeholder: "e.g. C01234abc",
    submitLabel: "Connect workspace",
  },
  vercel: {
    label: "Team ID",
    placeholder: "e.g. team_xxxxxxxxxxxxxxxxxxxxxxxx",
    submitLabel: "Connect team",
  },
  okta: {
    label: "Org Domain",
    placeholder: "e.g. your-org.okta.com",
    submitLabel: "Connect organization",
  },
} as const satisfies Record<KnownProviderType, UidFieldDetails>;

const REGISTRY_UID_FIELD: UidFieldDetails = {
  label: "Provider UID",
  placeholder: "Enter the provider UID",
  submitLabel: "Connect provider",
};

export const UPDATE_SUBMIT_LABEL = "Save and test";

export function getUidFieldDetails(providerType: string): UidFieldDetails {
  return Object.hasOwn(UID_FIELD_DETAILS, providerType)
    ? UID_FIELD_DETAILS[providerType as KnownProviderType]
    : REGISTRY_UID_FIELD;
}

/** The form field an account-level API error lands on. */
export const UID_FIELD = ProviderCredentialFields.PROVIDER_UID;
