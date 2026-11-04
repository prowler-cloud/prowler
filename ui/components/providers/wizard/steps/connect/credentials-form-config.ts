import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { isCloud } from "@/lib/shared/env";
import {
  addCredentialsFormSchema,
  addCredentialsRoleFormSchema,
  addCredentialsServiceAccountFormSchema,
} from "@/types/formSchemas";
import type { KnownProviderType } from "@/types/providers";

/** The credentials schema for a provider and access method. */
export function getCredentialsFormSchema(
  providerType: KnownProviderType,
  via: string | null,
) {
  if (providerType === "aws" && via === "role") {
    return addCredentialsRoleFormSchema(providerType);
  }
  if (providerType === "alibabacloud" && via === "role") {
    return addCredentialsRoleFormSchema(providerType);
  }
  if (providerType === "gcp" && via === "service-account") {
    return addCredentialsServiceAccountFormSchema(providerType);
  }
  // GitHub, M365 and Cloudflare require different fields per method.
  if (
    providerType === "github" ||
    providerType === "m365" ||
    providerType === "cloudflare"
  ) {
    return addCredentialsFormSchema(providerType, via);
  }
  return addCredentialsFormSchema(providerType);
}

interface CredentialsDefaultsContext {
  /** Prefills secrets that repeat the account id (OCI tenancy, Workspace customer). */
  providerUid?: string;
  externalId: string;
}

/** Empty values for every credentials field of a provider and access method. */
export function getCredentialsFormDefaults(
  providerType: KnownProviderType,
  via: string | null,
  { providerUid, externalId }: CredentialsDefaultsContext,
): Record<string, string> {
  const baseDefaults = {
    [ProviderCredentialFields.PROVIDER_ID]: "",
    [ProviderCredentialFields.PROVIDER_TYPE]: providerType,
  };

  // AWS Role credentials
  if (providerType === "aws" && via === "role") {
    const isCloudEnv = isCloud();
    const defaultCredentialsType = isCloudEnv
      ? "aws-sdk-default"
      : "access-secret-key";
    return {
      ...baseDefaults,
      [ProviderCredentialFields.CREDENTIALS_TYPE]: defaultCredentialsType,
      [ProviderCredentialFields.ROLE_ARN]: "",
      [ProviderCredentialFields.EXTERNAL_ID]: externalId,
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
      [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
      [ProviderCredentialFields.ROLE_SESSION_NAME]: "",
      [ProviderCredentialFields.SESSION_DURATION]: "3600",
    };
  }

  // GCP Service Account
  if (providerType === "gcp" && via === "service-account") {
    return {
      ...baseDefaults,
      [ProviderCredentialFields.SERVICE_ACCOUNT_KEY]: "",
    };
  }

  switch (providerType) {
    case "aws":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: "",
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: "",
        [ProviderCredentialFields.AWS_SESSION_TOKEN]: "",
      };
    case "azure":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.CLIENT_ID]: "",
        [ProviderCredentialFields.CLIENT_SECRET]: "",
        [ProviderCredentialFields.TENANT_ID]: "",
      };
    case "m365":
      // M365 credentials based on via parameter
      if (via === "app_client_secret") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.CLIENT_SECRET]: "",
          [ProviderCredentialFields.TENANT_ID]: "",
        };
      }
      if (via === "app_certificate") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLIENT_ID]: "",
          [ProviderCredentialFields.CERTIFICATE_CONTENT]: "",
          [ProviderCredentialFields.TENANT_ID]: "",
        };
      }
      return {
        ...baseDefaults,
        [ProviderCredentialFields.CLIENT_ID]: "",
        [ProviderCredentialFields.TENANT_ID]: "",
      };
    case "gcp":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.CLIENT_ID]: "",
        [ProviderCredentialFields.CLIENT_SECRET]: "",
        [ProviderCredentialFields.REFRESH_TOKEN]: "",
      };
    case "kubernetes":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.KUBECONFIG_CONTENT]: "",
      };
    case "github":
      // GitHub credentials based on via parameter
      if (via === "personal_access_token") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.PERSONAL_ACCESS_TOKEN]: "",
        };
      }
      if (via === "oauth_app") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.OAUTH_APP_TOKEN]: "",
        };
      }
      if (via === "github_app") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.GITHUB_APP_ID]: "",
          [ProviderCredentialFields.GITHUB_APP_KEY]: "",
        };
      }
      return baseDefaults;
    case "oraclecloud":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.OCI_USER]: "",
        [ProviderCredentialFields.OCI_FINGERPRINT]: "",
        [ProviderCredentialFields.OCI_KEY_CONTENT]: "",
        [ProviderCredentialFields.OCI_TENANCY]: providerUid || "",
        [ProviderCredentialFields.OCI_REGION]: "",
        [ProviderCredentialFields.OCI_PASS_PHRASE]: "",
      };
    case "mongodbatlas":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.ATLAS_PUBLIC_KEY]: "",
        [ProviderCredentialFields.ATLAS_PRIVATE_KEY]: "",
      };
    case "alibabacloud":
      if (via === "role") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.ALIBABACLOUD_ROLE_ARN]: "",
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]: "",
          [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]: "",
          [ProviderCredentialFields.ALIBABACLOUD_ROLE_SESSION_NAME]: "",
        };
      }
      return {
        ...baseDefaults,
        [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_ID]: "",
        [ProviderCredentialFields.ALIBABACLOUD_ACCESS_KEY_SECRET]: "",
      };
    case "cloudflare":
      // Cloudflare credentials based on via parameter
      if (via === "api_token") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLOUDFLARE_API_TOKEN]: "",
        };
      }
      if (via === "api_key") {
        return {
          ...baseDefaults,
          [ProviderCredentialFields.CLOUDFLARE_API_KEY]: "",
          [ProviderCredentialFields.CLOUDFLARE_API_EMAIL]: "",
        };
      }
      return baseDefaults;
    case "openstack":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CONTENT]: "",
        [ProviderCredentialFields.OPENSTACK_CLOUDS_YAML_CLOUD]: "",
      };
    case "googleworkspace":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.GOOGLEWORKSPACE_CUSTOMER_ID]:
          providerUid || "",
        [ProviderCredentialFields.GOOGLEWORKSPACE_CREDENTIALS_CONTENT]: "",
        [ProviderCredentialFields.GOOGLEWORKSPACE_DELEGATED_USER]: "",
      };
    case "image":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.REGISTRY_USERNAME]: "",
        [ProviderCredentialFields.REGISTRY_PASSWORD]: "",
        [ProviderCredentialFields.REGISTRY_TOKEN]: "",
        [ProviderCredentialFields.IMAGE_FILTER]: "",
        [ProviderCredentialFields.TAG_FILTER]: "",
      };
    case "vercel":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.VERCEL_API_TOKEN]: "",
      };
    case "okta":
      return {
        ...baseDefaults,
        [ProviderCredentialFields.OKTA_CLIENT_ID]: "",
        [ProviderCredentialFields.OKTA_PRIVATE_KEY]: "",
      };
    default:
      return baseDefaults;
  }
}
