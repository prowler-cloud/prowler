import { revalidatePath } from "next/cache";

import {
  filterEmptyValues,
  getErrorMessage,
  getFormValue,
  parseStringify,
} from "@/lib";
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
    ...buildAzureSecret(formData),
    [ProviderCredentialFields.USER]: getFormValue(
      formData,
      ProviderCredentialFields.USER,
    ),
    [ProviderCredentialFields.PASSWORD]: getFormValue(
      formData,
      ProviderCredentialFields.PASSWORD,
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

// Main function to build secret configuration
export const buildSecretConfig = (
  formData: FormData,
  providerType: ProviderType,
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
  };

  const builder = secretBuilders[providerType];
  if (!builder) {
    throw new Error(`Unsupported provider type: ${providerType}`);
  }

  return builder();
};

// Helper function to build secret for update (reuses existing logic)
export const buildUpdateSecretConfig = (
  formData: FormData,
  providerType: ProviderType,
) => {
  // Reuse the same secret building logic as add, but only return the secret
  const { secret } = buildSecretConfig(formData, providerType);

  // Handle special case for M365 password field inconsistency
  if (providerType === "m365") {
    return {
      ...secret,
      password: formData.get(ProviderCredentialFields.PASSWORD),
    };
  }

  return secret;
};

// Helper function to handle API responses consistently
export const handleApiResponse = async (
  response: Response,
  pathToRevalidate?: string,
) => {
  const data = await response.json();

  if (pathToRevalidate) {
    revalidatePath(pathToRevalidate);
  }

  return parseStringify(data);
};

// Helper function to handle API errors consistently
export const handleApiError = (error: unknown) => {
  console.error(error);
  return {
    error: getErrorMessage(error),
  };
};
