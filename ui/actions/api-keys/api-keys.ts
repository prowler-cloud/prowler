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

import { adaptApiKeysResponse } from "./api-keys.adapter";

interface GetApiKeysParams {
  page?: number;
  pageSize?: number;
  sort?: string;
}

/**
 * Fetches API keys for the current tenant with pagination support
 * Returns enriched API keys with user data already resolved and pagination metadata
 */
export const getApiKeys = async (params?: GetApiKeysParams) => {
  const { page = 1, pageSize = 10, sort } = params || {};

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/api-keys`);
  url.searchParams.set("include", "entity.roles");
  url.searchParams.set("page[number]", page.toString());
  url.searchParams.set("page[size]", pageSize.toString());

  if (sort) {
    url.searchParams.set("sort", sort);
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
      next: { tags: ["api-keys"] },
    });

    const apiResponse = (await handleApiResponse(response)) as ApiKeyResponse;

    return adaptApiKeysResponse(apiResponse);
  } catch (error) {
    console.error("Error fetching API keys:", error);
    return { data: [], metadata: undefined };
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
    revalidateTag("api-keys", "max");

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
    revalidateTag("api-keys", "max");

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
      const errorData = handleApiError(response);
      return { error: errorData.error };
    }

    // Revalidate the api-keys list
    revalidateTag("api-keys", "max");

    return { success: true };
  } catch (error) {
    console.error("Error revoking API key:", error);
    return {
      error:
        error instanceof Error ? error.message : "Failed to revoke API key",
    };
  }
};
