"use server";

import { revalidatePath } from "next/cache";

import { APIKey, APIKeyCreateData, APIKeyCreateResponse } from "@/types/users";

import { buildURL, getHeaders } from "../util";

export async function getAPIKeys(): Promise<{ data: APIKey[] }> {
  const response = await fetch(buildURL(`/api-keys`), {
    cache: "no-store",
    headers: getHeaders(),
  });

  if (!response.ok) {
    throw new Error("Failed to fetch API keys");
  }

  return response.json();
}

export async function createAPIKey(
  data: APIKeyCreateData,
): Promise<APIKeyCreateResponse> {
  const body = {
    data: {
      type: "api-keys",
      attributes: data,
    },
  };

  const response = await fetch(buildURL("/api-keys"), {
    method: "POST",
    headers: getHeaders(),
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
  const response = await fetch(buildURL(`/api-keys/${apiKeyId}`), {
    method: "DELETE",
    headers: getHeaders(),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Failed to revoke API key");
  }

  revalidatePath("/profile");
} 