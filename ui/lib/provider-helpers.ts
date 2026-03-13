import { checkConnectionProvider } from "@/actions/providers/providers";
import { getTask } from "@/actions/task/tasks";
import {
  ProviderEntity,
  ProviderProps,
  ProvidersApiResponse,
  ProviderType,
} from "@/types/providers";

import { checkTaskStatus } from "./helper";

export const extractProviderUIDs = (
  providersData: ProvidersApiResponse,
): string[] => {
  if (!providersData?.data) return [];

  return Array.from(
    new Set(
      providersData.data
        .map((provider: ProviderProps) => provider.attributes?.uid)
        .filter(Boolean),
    ),
  );
};

export const extractProviderIds = (
  providersData: ProvidersApiResponse,
): string[] => {
  if (!providersData?.data) return [];

  return providersData.data
    .map((provider: ProviderProps) => provider.id)
    .filter(Boolean);
};

export const createProviderDetailsMapping = (
  providerUIDs: string[],
  providersData: ProvidersApiResponse,
): Array<{ [uid: string]: ProviderEntity }> => {
  if (!providersData?.data) return [];

  return providerUIDs.map((uid) => {
    const provider = providersData.data.find(
      (p: { attributes: { uid: string } }) => p.attributes?.uid === uid,
    );

    return {
      [uid]: {
        provider: provider?.attributes?.provider || "aws",
        uid: uid,
        alias: provider?.attributes?.alias ?? null,
      },
    };
  });
};

export const createProviderDetailsMappingById = (
  providerIds: string[],
  providersData: ProvidersApiResponse,
): Array<{ [id: string]: ProviderEntity }> => {
  if (!providersData?.data) return [];

  return providerIds.map((id) => {
    const provider = providersData.data.find((p: ProviderProps) => p.id === id);

    return {
      [id]: {
        provider: provider?.attributes?.provider || "aws",
        uid: provider?.attributes?.uid || "",
        alias: provider?.attributes?.alias ?? null,
      },
    };
  });
};

// Helper function to determine which form type to show
export type ProviderFormType =
  | "selector"
  | "credentials"
  | "role"
  | "service-account"
  | null;

export const getProviderFormType = (
  providerType: ProviderType,
  via?: string,
): ProviderFormType => {
  // Providers that need credential type selection
  const needsSelector = [
    "aws",
    "gcp",
    "github",
    "m365",
    "alibabacloud",
    "cloudflare",
  ].includes(providerType);

  // Show selector if no via parameter and provider needs it
  if (needsSelector && !via) {
    return "selector";
  }

  // AWS specific forms
  if (providerType === "aws") {
    if (via === "role") return "role";
    if (via === "credentials") return "credentials";
  }

  // GCP specific forms
  if (providerType === "gcp") {
    if (via === "service-account") return "service-account";
    if (via === "credentials") return "credentials";
  }

  // GitHub credential types
  if (
    providerType === "github" &&
    ["personal_access_token", "oauth_app", "github_app"].includes(via || "")
  ) {
    return "credentials";
  }

  // M365 credential types
  if (
    providerType === "m365" &&
    ["app_client_secret", "app_certificate"].includes(via || "")
  ) {
    return "credentials";
  }

  // AlibabaCloud specific forms
  if (providerType === "alibabacloud") {
    if (via === "role") return "role";
    if (via === "credentials") return "credentials";
  }

  // Cloudflare credential types
  if (
    providerType === "cloudflare" &&
    ["api_token", "api_key"].includes(via || "")
  ) {
    return "credentials";
  }

  // Other providers go directly to credentials form
  if (!needsSelector) {
    return "credentials";
  }

  return null;
};

// Helper to check if back button should be shown based on via parameter
export const requiresBackButton = (via?: string | null): boolean => {
  if (!via) return false;

  const validViaTypes = [
    "credentials",
    "role",
    "service-account",
    "personal_access_token",
    "oauth_app",
    "github_app",
    "app_client_secret",
    "app_certificate",
    "api_token",
    "api_key",
  ];
  // Note: "role" is already included for AWS, now also used by AlibabaCloud
  // "api_token" and "api_key" are used by Cloudflare

  return validViaTypes.includes(via);
};

export interface TestConnectionResult {
  connected: boolean;
  error: string | null;
}

/**
 * Tests a provider's connection end-to-end: submits the task, polls until
 * completion, and returns the real connection result.
 *
 * Used by both the Provider Wizard (single) and bulk test (via concurrency limit).
 */
export async function testProviderConnection(
  providerId: string,
): Promise<TestConnectionResult> {
  const formData = new FormData();
  formData.append("providerId", providerId);

  const data = await checkConnectionProvider(formData);

  if (data?.errors && data.errors.length > 0) {
    return {
      connected: false,
      error: data.errors[0]?.detail ?? "Unknown error",
    };
  }

  const taskId = data?.data?.id;
  if (!taskId) {
    return { connected: false, error: "No task ID returned" };
  }

  const taskResult = await checkTaskStatus(taskId);

  if (!taskResult.completed) {
    return {
      connected: false,
      error: taskResult.error ?? "Connection test timed out",
    };
  }

  const task = await getTask(taskId);
  const { connected, error } = task.data.attributes.result;

  return {
    connected,
    error: connected ? null : error || "Unknown error",
  };
}
