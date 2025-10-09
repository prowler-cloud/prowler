"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";

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
 * Get tenant lighthouse configuration
 */
export const getTenantConfig = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/lighthouse/config`);

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
  const url = new URL(`${apiBaseUrl}/lighthouse/config`);

  try {
    const payload = {
      data: {
        type: "lighthouse-config",
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
