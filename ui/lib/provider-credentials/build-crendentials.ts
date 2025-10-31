import { filterEmptyValues, getFormValue } from "@/lib";
import { ProviderType } from "@/types";

import { ProviderCredentialFields } from "./provider-credential-fields";

// Helper functions for each provider type
export const buildAWSSecret = (formData: FormData, isRole: boolean) => {
  if (isRole) {
    const secret = {
      [ProviderCredentialFields.ROLE_ARN]: getFormValue(
        formData,
        ProviderCredentialFields.ROLE_ARN,
      ),
      [ProviderCredentialFields.EXTERNAL_ID]: getFormValue(
        formData,
        ProviderCredentialFields.EXTERNAL_ID,
      ),
      [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: getFormValue(
        formData,
        ProviderCredentialFields.AWS_ACCESS_KEY_ID,
      ),
      [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: getFormValue(
        formData,
        ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
      ),
      [ProviderCredentialFields.AWS_SESSION_TOKEN]: getFormValue(
        formData,
        ProviderCredentialFields.AWS_SESSION_TOKEN,
      ),
      session_duration:
        parseInt(
          getFormValue(
            formData,
            ProviderCredentialFields.SESSION_DURATION,
          ) as string,
          10,
        ) || 3600,
      [ProviderCredentialFields.ROLE_SESSION_NAME]: getFormValue(
        formData,
        ProviderCredentialFields.ROLE_SESSION_NAME,
      ),
    };
    return filterEmptyValues(secret);
  }

  const secret = {
    [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: getFormValue(
      formData,
      ProviderCredentialFields.AWS_ACCESS_KEY_ID,
    ),
    [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: getFormValue(
      formData,
      ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
    ),
    [ProviderCredentialFields.AWS_SESSION_TOKEN]: getFormValue(
      formData,
      ProviderCredentialFields.AWS_SESSION_TOKEN,
    ),
  };
  return filterEmptyValues(secret);
};

export const buildAzureSecret = (formData: FormData) => {
  const secret = {
    [ProviderCredentialFields.CLIENT_ID]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_ID,
    ),
    [ProviderCredentialFields.CLIENT_SECRET]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_SECRET,
    ),
    [ProviderCredentialFields.TENANT_ID]: getFormValue(
      formData,
      ProviderCredentialFields.TENANT_ID,
    ),
  };
  return filterEmptyValues(secret);
};

export const buildM365Secret = (formData: FormData) => {
  const secret = {
    [ProviderCredentialFields.CLIENT_ID]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_ID,
    ),
    [ProviderCredentialFields.TENANT_ID]: getFormValue(
      formData,
      ProviderCredentialFields.TENANT_ID,
    ),
    [ProviderCredentialFields.CLIENT_SECRET]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_SECRET,
    ),
    [ProviderCredentialFields.CERTIFICATE_CONTENT]: getFormValue(
      formData,
      ProviderCredentialFields.CERTIFICATE_CONTENT,
    ),
  };
  return filterEmptyValues(secret);
};

export const buildGCPSecret = (
  formData: FormData,
  isServiceAccount: boolean,
) => {
  if (isServiceAccount) {
    const serviceAccountKeyRaw = getFormValue(
      formData,
      ProviderCredentialFields.SERVICE_ACCOUNT_KEY,
    ) as string;

    try {
      return {
        service_account_key: JSON.parse(serviceAccountKeyRaw),
      };
    } catch (error) {
      console.error("Invalid service account key JSON:", error);
      throw new Error("Invalid service account key format");
    }
  }

  const secret = {
    [ProviderCredentialFields.CLIENT_ID]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_ID,
    ),
    [ProviderCredentialFields.CLIENT_SECRET]: getFormValue(
      formData,
      ProviderCredentialFields.CLIENT_SECRET,
    ),
    [ProviderCredentialFields.REFRESH_TOKEN]: getFormValue(
      formData,
      ProviderCredentialFields.REFRESH_TOKEN,
    ),
  };
  return filterEmptyValues(secret);
};

export const buildKubernetesSecret = (formData: FormData) => {
  const secret = {
    [ProviderCredentialFields.KUBECONFIG_CONTENT]: getFormValue(
      formData,
      ProviderCredentialFields.KUBECONFIG_CONTENT,
    ),
  };
  return filterEmptyValues(secret);
};

export const buildGitHubSecret = (formData: FormData) => {
  // Check which authentication method is being used
  const hasPersonalToken =
    formData.get(ProviderCredentialFields.PERSONAL_ACCESS_TOKEN) !== null &&
    formData.get(ProviderCredentialFields.PERSONAL_ACCESS_TOKEN) !== "";
  const hasOAuthToken =
    formData.get(ProviderCredentialFields.OAUTH_APP_TOKEN) !== null &&
    formData.get(ProviderCredentialFields.OAUTH_APP_TOKEN) !== "";
  const hasGitHubApp =
    formData.get(ProviderCredentialFields.GITHUB_APP_ID) !== null &&
    formData.get(ProviderCredentialFields.GITHUB_APP_ID) !== "";

  if (hasPersonalToken) {
    const secret = {
      [ProviderCredentialFields.PERSONAL_ACCESS_TOKEN]: getFormValue(
        formData,
        ProviderCredentialFields.PERSONAL_ACCESS_TOKEN,
      ),
    };
    return filterEmptyValues(secret);
  }

  if (hasOAuthToken) {
    const secret = {
      [ProviderCredentialFields.OAUTH_APP_TOKEN]: getFormValue(
        formData,
        ProviderCredentialFields.OAUTH_APP_TOKEN,
      ),
    };
    return filterEmptyValues(secret);
  }

  if (hasGitHubApp) {
    const secret = {
      [ProviderCredentialFields.GITHUB_APP_ID]: getFormValue(
        formData,
        ProviderCredentialFields.GITHUB_APP_ID,
      ),
      [ProviderCredentialFields.GITHUB_APP_KEY]: getFormValue(
        formData,
        ProviderCredentialFields.GITHUB_APP_KEY,
      ),
    };
    return filterEmptyValues(secret);
  }

  // If no credentials are provided, return empty object
  return {};
};

/**
 * Utility function to safely encode a string to base64
 * Handles UTF-8 characters properly without using deprecated APIs
 */
const base64Encode = (str: string): string => {
  if (!str) return "";
  // Convert string to UTF-8 bytes, then to base64
  const utf8Bytes = new TextEncoder().encode(str);
  // Convert Uint8Array to binary string without spread operator
  let binaryString = "";
  for (let i = 0; i < utf8Bytes.length; i++) {
    binaryString += String.fromCharCode(utf8Bytes[i]);
  }
  return btoa(binaryString);
};

export const buildOracleCloudSecret = (
  formData: FormData,
  providerUid?: string,
) => {
  const keyContent = getFormValue(
    formData,
    ProviderCredentialFields.OCI_KEY_CONTENT,
  ) as string;

  // Base64 encode the key content for the backend
  // Uses modern TextEncoder API to properly handle UTF-8 characters
  const encodedKeyContent = base64Encode(keyContent);

  const secret = {
    [ProviderCredentialFields.OCI_USER]: getFormValue(
      formData,
      ProviderCredentialFields.OCI_USER,
    ),
    [ProviderCredentialFields.OCI_FINGERPRINT]: getFormValue(
      formData,
      ProviderCredentialFields.OCI_FINGERPRINT,
    ),
    [ProviderCredentialFields.OCI_KEY_CONTENT]: encodedKeyContent,
    [ProviderCredentialFields.OCI_TENANCY]:
      providerUid ||
      getFormValue(formData, ProviderCredentialFields.OCI_TENANCY),
    [ProviderCredentialFields.OCI_REGION]: getFormValue(
      formData,
      ProviderCredentialFields.OCI_REGION,
    ),
    [ProviderCredentialFields.OCI_PASS_PHRASE]: getFormValue(
      formData,
      ProviderCredentialFields.OCI_PASS_PHRASE,
    ),
  };
  return filterEmptyValues(secret);
};

// Main function to build secret configuration
export const buildSecretConfig = (
  formData: FormData,
  providerType: ProviderType,
  providerUid?: string,
) => {
  const isRole = formData.get(ProviderCredentialFields.ROLE_ARN) !== null;
  const isServiceAccount =
    formData.get(ProviderCredentialFields.SERVICE_ACCOUNT_KEY) !== null;

  const secretBuilders = {
    aws: () => ({
      secretType: isRole ? "role" : "static",
      secret: buildAWSSecret(formData, isRole),
    }),
    azure: () => ({
      secretType: "static",
      secret: buildAzureSecret(formData),
    }),
    m365: () => ({
      secretType: "static",
      secret: buildM365Secret(formData),
    }),
    gcp: () => ({
      secretType: isServiceAccount ? "service_account" : "static",
      secret: buildGCPSecret(formData, isServiceAccount),
    }),
    kubernetes: () => ({
      secretType: "static",
      secret: buildKubernetesSecret(formData),
    }),
    github: () => ({
      secretType: "static",
      secret: buildGitHubSecret(formData),
    }),
    oci: () => ({
      secretType: "static",
      secret: buildOracleCloudSecret(formData, providerUid),
    }),
  };

  const builder = secretBuilders[providerType];
  if (!builder) {
    throw new Error(`Unsupported provider type: ${providerType}`);
  }

  return builder();
};
