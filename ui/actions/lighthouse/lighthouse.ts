"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import {
  validateBaseUrl,
  validateCredentials,
} from "@/lib/lighthouse/validation";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  type LighthouseProvider,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/lighthouse";
import type {
  BedrockCredentials,
  OpenAICompatibleCredentials,
  OpenAICredentials,
} from "@/types/lighthouse/credentials";

// API Response Types
type ProviderCredentials =
  | OpenAICredentials
  | BedrockCredentials
  | OpenAICompatibleCredentials;

interface ApiError {
  detail: string;
}

interface ApiLinks {
  next?: string;
}

interface ApiResponse<T> {
  data?: T;
  errors?: ApiError[];
  links?: ApiLinks;
}

interface LighthouseModelAttributes {
  model_id: string;
  model_name: string;
}

interface LighthouseModel {
  id: string;
  attributes: LighthouseModelAttributes;
}

interface LighthouseProviderAttributes {
  provider_type: string;
  credentials: ProviderCredentials;
  base_url?: string;
  is_active: boolean;
}

interface LighthouseProviderResource {
  id: string;
  attributes: LighthouseProviderAttributes;
}

interface ModelOption {
  id: string;
  name: string;
}

interface ProviderCredentialsAttributes {
  credentials: ProviderCredentials;
  base_url?: string;
}

interface ProviderCredentialsResponse {
  attributes: ProviderCredentialsAttributes;
}

/**
 * Create a new lighthouse provider configuration
 */
export const createLighthouseProvider = async (config: {
  provider_type: LighthouseProvider;
  credentials: ProviderCredentials;
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

    return handleApiResponse(response, "/lighthouse/config");
  } catch (error) {
    return handleApiError(error);
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

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
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

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
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

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Get only model identifiers and names for a provider type.
 * Uses sparse fieldsets to only fetch model_id and model_name, avoiding over-fetching.
 * Fetches all pages automatically.
 */
export const getLighthouseModelIds = async (
  providerType: LighthouseProvider,
) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/lighthouse/models`);
  url.searchParams.set("filter[provider_type]", providerType);
  url.searchParams.set("fields[lighthouse-models]", "model_id,model_name");

  try {
    // Fetch first page
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await handleApiResponse(response);

    if (data.errors) {
      return data;
    }

    const allModels: LighthouseModel[] = [...(data.data || [])];

    // Fetch remaining pages
    let nextUrl = data.links?.next;
    while (nextUrl) {
      const pageResponse = await fetch(nextUrl, {
        method: "GET",
        headers,
      });

      const pageData = await handleApiResponse(pageResponse);

      if (pageData.errors) {
        return pageData;
      }

      if (pageData.data && Array.isArray(pageData.data)) {
        allModels.push(...pageData.data);
      }

      nextUrl = pageData.links?.next;
    }

    // Transform to minimal format
    const models: ModelOption[] = allModels
      .map((m: LighthouseModel) => ({
        id: m.attributes.model_id,
        name: m.attributes.model_name || m.attributes.model_id,
      }))
      .filter((v: ModelOption) => typeof v.id === "string");

    return { data: models };
  } catch (error) {
    return handleApiError(error);
  }
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

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Update tenant lighthouse configuration
 */
export const updateTenantConfig = async (config: {
  default_models?: Record<string, string>;
  default_provider?: LighthouseProvider;
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

    return handleApiResponse(response, "/lighthouse/config");
  } catch (error) {
    return handleApiError(error);
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
  providerType?: LighthouseProvider,
): Promise<{
  credentials: ProviderCredentials | Record<string, never>;
  base_url?: string;
}> => {
  const headers = await getAuthHeaders({ contentType: false });

  // Note: fields[lighthouse-providers]=credentials is required to get decrypted credentials
  // base_url is not sensitive and is returned by default
  const url = new URL(`${apiBaseUrl}/lighthouse/providers`);
  if (providerType) {
    url.searchParams.append("filter[provider_type]", providerType);
  }
  url.searchParams.append("filter[is_active]", "true");
  url.searchParams.append(
    "fields[lighthouse-providers]",
    "credentials,base_url",
  );

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data: ApiResponse<ProviderCredentialsResponse[]> =
      await response.json();

    if (data?.data && data.data.length > 0) {
      const provider = data.data[0]?.attributes;
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
      providers.data.some(
        (p: LighthouseProviderResource) => p.attributes?.is_active,
      );

    return hasTenantConfig && hasActiveProvider;
  } catch (error) {
    console.error("[Server] Error in isLighthouseConfigured:", error);
    return false;
  }
};

/**
 * Get a single lighthouse provider by provider type
 * Server-side only - never exposes internal IDs to client
 */
export const getLighthouseProviderByType = async (
  providerType: LighthouseProvider,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse/providers`);
  url.searchParams.set("filter[provider_type]", providerType);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await handleApiResponse(response);

    if (data.errors) {
      return data;
    }

    // Should only be one config per provider type per tenant
    if (data.data && data.data.length > 0) {
      return { data: data.data[0] };
    }

    return { errors: [{ detail: "Provider configuration not found" }] };
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Update a lighthouse provider configuration by provider type
 * Looks up the provider server-side, never exposes ID to client
 */
export const updateLighthouseProviderByType = async (
  providerType: LighthouseProvider,
  config: {
    credentials?: ProviderCredentials;
    base_url?: string;
    is_active?: boolean;
  },
) => {
  try {
    // Validate credentials if provided
    if (config.credentials && Object.keys(config.credentials).length > 0) {
      const credentialsValidation = validateCredentials(
        providerType,
        config.credentials as Record<string, string>,
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

    return handleApiResponse(response, "/lighthouse/config");
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Delete a lighthouse provider configuration by provider type
 * Looks up the provider server-side, never exposes ID to client
 */
export const deleteLighthouseProviderByType = async (
  providerType: LighthouseProvider,
) => {
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

    return handleApiResponse(response, "/lighthouse/config");
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Get lighthouse providers configuration with all available models
 * Fetches all models for each provider to populate the model selector
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
      providers?.data?.filter(
        (p: LighthouseProviderResource) => p.attributes?.is_active,
      ) || [];

    const providersConfig = await Promise.all(
      activeProviders.map(async (provider: LighthouseProviderResource) => {
        const providerType = provider.attributes
          .provider_type as LighthouseProvider;

        // Fetch all models for this provider
        const modelsResponse = await getLighthouseModelIds(providerType);
        const models: ModelOption[] = modelsResponse.data || [];

        return {
          id: providerType,
          name: PROVIDER_DISPLAY_NAMES[providerType],
          models: models,
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
