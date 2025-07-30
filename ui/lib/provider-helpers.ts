import {
  ProviderEntity,
  ProviderProps,
  ProvidersApiResponse,
  ProviderType,
} from "@/types/providers";

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
  const needsSelector = ["aws", "gcp", "github"].includes(providerType);
  
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
  if (providerType === "github" && 
      ["personal_access_token", "oauth_app", "github_app"].includes(via || "")) {
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
  ];
  
  return validViaTypes.includes(via);
};
