"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import {
  validateBaseUrl,
  validateCredentials,
} from "@/lib/lighthouse/validation";

/**
 * Create a new lighthouse provider configuration
 */
export const createLighthouseProvider = async (config: {
  provider_type: string;
  credentials: Record<string, any>;
  base_url?: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/lighthouse/providers`);

  try {
    // Validate credentials
    const credentialsValidation = validateCredentials(
      config.provider_type,
      config.credentials,
    );
    if (!credentialsValidation.success) {
      return {
        errors: [{ detail: credentialsValidation.error }],
      };
    }

    // Validate base_url if provided
    if (config.base_url) {
      const baseUrlValidation = validateBaseUrl(config.base_url);
      if (!baseUrlValidation.success) {
        return {
          errors: [{ detail: baseUrlValidation.error }],
        };
      }
    }

    const payload = {
      data: {
        type: "lighthouse-providers",
        attributes: {
          provider_type: config.provider_type,
          credentials: config.credentials,
          base_url: config.base_url || null,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in createLighthouseProvider:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Test provider connection (returns task)
 */
export const testProviderConnection = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/lighthouse/providers/${providerId}/connection`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in testProviderConnection:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Refresh provider models (returns task)
 */
export const refreshProviderModels = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/lighthouse/providers/${providerId}/refresh-models`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in refreshProviderModels:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Get all lighthouse providers
 */
export const getLighthouseProviders = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse/providers`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in getLighthouseProviders:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Get lighthouse provider models (fetches all pages)
 */
export const getLighthouseModels = async (providerType: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  let url: string | null =
    `${apiBaseUrl}/lighthouse/models?filter[provider_type]=${providerType}`;
  const allModels: any[] = [];

  try {
    // Fetch all pages
    while (url) {
      const response = await fetch(url, {
        method: "GET",
        headers,
      });

      const data = await response.json();

      if (data.errors) {
        return data;
      }

      // Accumulate models from this page
      if (data.data && Array.isArray(data.data)) {
        allModels.push(...data.data);
      }

      // Check for next page
      url = data.links?.next || null;
    }

    return { data: allModels };
  } catch (error) {
    console.error("[Server] Error in getLighthouseModels:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Get only model identifiers and names for a provider type.
 * Returns minimal data to the client to avoid over-serializing API payloads.
 */
export const getLighthouseModelIds = async (
  providerType: string,
): Promise<{
  data?: Array<{ id: string; name: string }>;
  errors?: Array<{ detail: string }>;
}> => {
  const result = await getLighthouseModels(providerType);
  if ((result as any).errors) return result as any;
  const models = Array.isArray((result as any).data)
    ? (result as any).data
        .map((m: any) => ({
          id: m?.attributes?.model_id,
          name: m?.attributes?.model_name || m?.attributes?.model_id,
        }))
        .filter((v: any) => typeof v.id === "string")
    : [];
  return { data: models };
};

/**
 * Get tenant lighthouse configuration
 */
export const getTenantConfig = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse/configuration`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in getTenantConfig:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Update tenant lighthouse configuration
 */
export const updateTenantConfig = async (config: {
  default_models?: Record<string, string>;
  default_provider?: string;
  business_context?: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/lighthouse/configuration`);

  try {
    const payload = {
      data: {
        type: "lighthouse-configurations",
        attributes: config,
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    revalidatePath("/lighthouse/config");
    return data;
  } catch (error) {
    console.error("[Server] Error in updateTenantConfig:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Get credentials and configuration from the specified provider (or first active provider)
 * Returns an object containing:
 * - credentials: varies by provider type
 *   - OpenAI: { api_key: string }
 *   - Bedrock: { access_key_id: string, secret_access_key: string, region: string }
 *   - OpenAI Compatible: { api_key: string }
 * - base_url: string | undefined (for OpenAI Compatible providers)
 */
export const getProviderCredentials = async (
  providerType?: string,
): Promise<{ credentials: Record<string, any>; base_url?: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  let url: string;

  // Note: fields[lighthouse-providers]=credentials is required to get decrypted credentials
  // base_url is not sensitive and is returned by default
  if (providerType) {
    url = `${apiBaseUrl}/lighthouse/providers?filter[provider_type]=${providerType}&filter[is_active]=true&fields[lighthouse-providers]=credentials,base_url`;
  } else {
    url = `${apiBaseUrl}/lighthouse/providers?filter[is_active]=true&fields[lighthouse-providers]=credentials,base_url`;
  }

  try {
    const response = await fetch(url, {
      method: "GET",
      headers,
    });

    const data = await response.json();

    if (data?.data && data.data.length > 0) {
      const provider = data.data[0].attributes;
      return {
        credentials: provider.credentials || {},
        base_url: provider.base_url,
      };
    }

    return { credentials: {} };
  } catch (error) {
    console.error("[Server] Error in getProviderCredentials:", error);
    return { credentials: {} };
  }
};

/**
 * Check if lighthouse is properly configured
 * Returns true if tenant config exists AND there's at least one active provider
 */
export const isLighthouseConfigured = async () => {
  try {
    const [tenantConfig, providers] = await Promise.all([
      getTenantConfig(),
      getLighthouseProviders(),
    ]);

    const hasTenantConfig = !!tenantConfig?.data;
    const hasActiveProvider =
      providers?.data &&
      Array.isArray(providers.data) &&
      providers.data.some((p: any) => p.attributes?.is_active);

    return hasTenantConfig && hasActiveProvider;
  } catch (error) {
    console.error("[Server] Error in isLighthouseConfigured:", error);
    return false;
  }
};

/**
 * Map provider type to display name
 */
const getProviderDisplayName = (providerType: string): string => {
  const displayNames: Record<string, string> = {
    openai: "OpenAI",
    bedrock: "Amazon Bedrock",
    openai_compatible: "OpenAI Compatible",
    anthropic: "Anthropic",
    google: "Google",
    azure: "Azure OpenAI",
  };
  return displayNames[providerType] || providerType;
};

/**
 * Get a single lighthouse provider by provider type
 * Server-side only - never exposes internal IDs to client
 */
export const getLighthouseProviderByType = async (providerType: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse/providers`);
  url.searchParams.set("filter[provider_type]", providerType);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();

    if (data.errors) {
      return data;
    }

    // Should only be one config per provider type per tenant
    if (data.data && data.data.length > 0) {
      return { data: data.data[0] };
    }

    return { errors: [{ detail: "Provider configuration not found" }] };
  } catch (error) {
    console.error("[Server] Error in getLighthouseProviderByType:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Update a lighthouse provider configuration by provider type
 * Looks up the provider server-side, never exposes ID to client
 */
export const updateLighthouseProviderByType = async (
  providerType: string,
  config: {
    credentials?: Record<string, any>;
    base_url?: string;
    is_active?: boolean;
  },
) => {
  try {
    // Validate credentials if provided
    if (config.credentials && Object.keys(config.credentials).length > 0) {
      const credentialsValidation = validateCredentials(
        providerType,
        config.credentials,
      );
      if (!credentialsValidation.success) {
        return {
          errors: [{ detail: credentialsValidation.error }],
        };
      }
    }

    // Validate base_url if provided
    if (config.base_url) {
      const baseUrlValidation = validateBaseUrl(config.base_url);
      if (!baseUrlValidation.success) {
        return {
          errors: [{ detail: baseUrlValidation.error }],
        };
      }
    }

    // First, get the provider by type
    const providerResult = await getLighthouseProviderByType(providerType);

    if (providerResult.errors || !providerResult.data) {
      return providerResult;
    }

    const providerId = providerResult.data.id;

    // Now update it
    const headers = await getAuthHeaders({ contentType: true });
    const url = new URL(`${apiBaseUrl}/lighthouse/providers/${providerId}`);

    const payload = {
      data: {
        type: "lighthouse-providers",
        id: providerId,
        attributes: config,
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    revalidatePath("/lighthouse/config");
    return data;
  } catch (error) {
    console.error("[Server] Error in updateLighthouseProviderByType:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Delete a lighthouse provider configuration by provider type
 * Looks up the provider server-side, never exposes ID to client
 */
export const deleteLighthouseProviderByType = async (providerType: string) => {
  try {
    // First, get the provider by type
    const providerResult = await getLighthouseProviderByType(providerType);

    if (providerResult.errors || !providerResult.data) {
      return providerResult;
    }

    const providerId = providerResult.data.id;

    // Now delete it
    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(`${apiBaseUrl}/lighthouse/providers/${providerId}`);

    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (response.status === 204 || response.status === 200) {
      revalidatePath("/lighthouse/config");
      return { success: true };
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[Server] Error in deleteLighthouseProviderByType:", error);
    return { errors: [{ detail: String(error) }] };
  }
};

/**
 * Get lighthouse providers configuration with default models
 * Returns only the default model for each provider to avoid loading hundreds of models
 */
export const getLighthouseProvidersConfig = async () => {
  try {
    const [tenantConfig, providers] = await Promise.all([
      getTenantConfig(),
      getLighthouseProviders(),
    ]);

    if (tenantConfig.errors || providers.errors) {
      return {
        errors: tenantConfig.errors || providers.errors,
      };
    }

    const tenantData = tenantConfig?.data?.attributes;
    const defaultProvider = tenantData?.default_provider || "";
    const defaultModels = tenantData?.default_models || {};

    // Filter only active providers
    const activeProviders =
      providers?.data?.filter((p: any) => p.attributes?.is_active) || [];

    // Build provider configuration with only default models
    const providersConfig = await Promise.all(
      activeProviders.map(async (provider: any) => {
        const providerType = provider.attributes.provider_type;
        const defaultModelId = defaultModels[providerType];

        // Fetch only the default model for this provider if it exists
        let defaultModel = null;
        if (defaultModelId) {
          const headers = await getAuthHeaders({ contentType: false });
          const url = `${apiBaseUrl}/lighthouse/models?filter[provider_type]=${providerType}&filter[model_id]=${defaultModelId}`;

          try {
            const response = await fetch(url, { method: "GET", headers });
            const data = await response.json();
            if (data.data && data.data.length > 0) {
              defaultModel = {
                id: data.data[0].attributes.model_id,
                name:
                  data.data[0].attributes.model_name ||
                  data.data[0].attributes.model_id,
              };
            }
          } catch (error) {
            console.error(
              `[Server] Error fetching default model for ${providerType}:`,
              error,
            );
          }
        }

        return {
          id: providerType,
          name: getProviderDisplayName(providerType),
          models: defaultModel ? [defaultModel] : [],
        };
      }),
    );

    // Filter out providers with no models
    const validProviders = providersConfig.filter((p) => p.models.length > 0);

    return {
      providers: validProviders,
      defaultProviderId: defaultProvider,
      defaultModelId: defaultModels[defaultProvider],
    };
  } catch (error) {
    console.error("[Server] Error in getLighthouseProvidersConfig:", error);
    return {
      errors: [{ detail: String(error) }],
    };
  }
};
