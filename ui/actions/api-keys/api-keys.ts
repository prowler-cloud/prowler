"use server";

import { revalidateTag } from "next/cache";

import {
  ApiKeyResponse,
  CreateApiKeyPayload,
  CreateApiKeyResponse,
  SingleApiKeyResponse,
  UpdateApiKeyPayload,
} from "@/components/users/profile/api-keys/types";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

/**
 * Fetches all API keys for the current tenant
 */
export const getApiKeys = async (): Promise<ApiKeyResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/api-keys`);

  try {
    const response = await fetch(url.toString(), {
      headers,
      next: { tags: ["api-keys"] },
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching API keys:", error);
    return undefined;
  }
};

/**
 * Creates a new API key
 * IMPORTANT: The full API key is only returned in this response, it cannot be retrieved again
 */
export const createApiKey = async (
  payload: CreateApiKeyPayload,
): Promise<
  | { data: CreateApiKeyResponse; error?: never }
  | { data?: never; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/api-keys`);

  const body = {
    data: {
      type: "api-keys",
      attributes: {
        name: payload.name,
        ...(payload.expires_at && { expires_at: payload.expires_at }),
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return handleApiError(response);
    }

    const data = (await handleApiResponse(response)) as CreateApiKeyResponse;

    // Revalidate the api-keys list
    revalidateTag("api-keys");

    return { data };
  } catch (error) {
    console.error("Error creating API key:", error);
    return {
      error:
        error instanceof Error ? error.message : "Failed to create API key",
    };
  }
};

/**
 * Updates an API key (only the name can be updated)
 */
export const updateApiKey = async (
  id: string,
  payload: UpdateApiKeyPayload,
): Promise<
  | { data: SingleApiKeyResponse; error?: never }
  | { data?: never; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/api-keys/${id}`);

  const body = {
    data: {
      type: "api-keys",
      id,
      attributes: {
        name: payload.name,
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return handleApiError(response);
    }

    const data = (await handleApiResponse(response)) as SingleApiKeyResponse;

    // Revalidate the api-keys list
    revalidateTag("api-keys");

    return { data };
  } catch (error) {
    console.error("Error updating API key:", error);
    return {
      error:
        error instanceof Error ? error.message : "Failed to update API key",
    };
  }
};

/**
 * Revokes an API key (cannot be undone)
 */
export const revokeApiKey = async (
  id: string,
): Promise<{ error?: string; success?: boolean }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/api-keys/${id}/revoke`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await handleApiError(response);
      return { error: errorData.error };
    }

    // Revalidate the api-keys list
    revalidateTag("api-keys");

    return { success: true };
  } catch (error) {
    console.error("Error revoking API key:", error);
    return {
      error:
        error instanceof Error ? error.message : "Failed to revoke API key",
    };
  }
};
