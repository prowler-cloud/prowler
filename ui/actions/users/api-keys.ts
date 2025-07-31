"use server";

import { revalidatePath } from "next/cache";

import { auth } from "@/auth.config";
import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import {
  APIKey,
  APIKeyCreateData,
  APIKeyCreateResponse,
  RoleDetail,
} from "@/types/users";

// UUID validation regex pattern
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validates if a string is a valid UUID
 */
function isValidUUID(uuid: string): boolean {
  return UUID_REGEX.test(uuid);
}

export async function getAPIKeys(): Promise<{ data: APIKey[] }> {
  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
  }

  // Validate tenantId format to prevent SSRF attacks
  if (!isValidUUID(session.tenantId)) {
    throw new Error("Invalid tenant ID format");
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/tenants/${session.tenantId}/api-keys`);

  const response = await fetch(url.toString(), {
    cache: "no-store",
    headers,
  });

  if (!response.ok) {
    throw new Error("Failed to fetch API keys");
  }

  return response.json();
}

export async function getRolesForAPIKeys(): Promise<{ data: RoleDetail[] }> {
  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/roles`);

  const response = await fetch(url.toString(), {
    cache: "no-store",
    headers,
  });

  if (!response.ok) {
    throw new Error("Failed to fetch roles");
  }

  return response.json();
}

export async function createAPIKey(
  data: APIKeyCreateData,
): Promise<APIKeyCreateResponse> {
  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
  }

  // Validate tenantId format to prevent SSRF attacks
  if (!isValidUUID(session.tenantId)) {
    throw new Error("Invalid tenant ID format");
  }

  // Validate role ID if provided
  if (data.role && !isValidUUID(data.role)) {
    throw new Error("Invalid role ID format");
  }

  const headers = await getAuthHeaders({ contentType: true });
  const body = {
    data: {
      type: "api-keys",
      attributes: {
        name: data.name,
        expiry_date: data.expiry_date,
        role: {
          type: "roles",
          id: data.role,
        },
      },
    },
  };

  const url = new URL(
    `${apiBaseUrl}/tenants/${session.tenantId}/api-keys/create`,
  );
  const response = await fetch(url.toString(), {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Failed to create API key");
  }

  revalidatePath("/profile");
  return response.json();
}

export async function revokeAPIKey(apiKeyId: string): Promise<{
  message: string;
  uuid: string;
  prefix: string;
}> {
  // Validate apiKeyId to prevent SSRF attacks
  if (!isValidUUID(apiKeyId)) {
    throw new Error("Invalid API key ID format");
  }

  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
  }

  // Validate tenantId as well for consistency
  if (!isValidUUID(session.tenantId)) {
    throw new Error("Invalid tenant ID format");
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/tenants/${session.tenantId}/api-keys/${apiKeyId}/revoke`,
  );

  const response = await fetch(url.toString(), {
    method: "DELETE",
    headers,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Failed to revoke API key");
  }

  // Parse the response to get confirmation details
  const result = await response.json();

  revalidatePath("/profile");
  return result;
}
