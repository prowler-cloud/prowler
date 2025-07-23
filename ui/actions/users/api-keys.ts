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

export async function getAPIKeys(): Promise<{ data: APIKey[] }> {
  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
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

  const headers = await getAuthHeaders({ contentType: true });
  const body = {
    data: {
      type: "api-keys",
      attributes: {
        name: data.name,
        expires_at: data.expires_at,
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

export async function revokeAPIKey(apiKeyId: string): Promise<void> {
  const session = await auth();
  if (!session?.tenantId) {
    throw new Error("No tenant ID found in session");
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

  revalidatePath("/profile");
}
