"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  handleApiError,
  handleApiResponse,
} from "@/lib";
import { ManageGroupPayload, ProviderGroupsResponse } from "@/types/components";

export const getProviderGroups = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string | number>;
  pageSize?: number;
}): Promise<ProviderGroupsResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/manage-groups");

  const url = new URL(`${apiBaseUrl}/provider-groups`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response, "/manage-groups");
  } catch (error) {
    console.error("Error fetching provider groups:", error);
    return undefined;
  }
};

export const getProviderGroupInfoById = async (providerGroupId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/provider-groups/${providerGroupId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    handleApiError(error);
  }
};

export const createProviderGroup = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const name = formData.get("name") as string;
  const providersJson = formData.get("providers") as string;
  const rolesJson = formData.get("roles") as string;

  // Parse JSON strings and handle empty cases
  const providers = providersJson ? JSON.parse(providersJson) : [];
  const roles = rolesJson ? JSON.parse(rolesJson) : [];

  // Prepare base payload
  const payload: any = {
    data: {
      type: "provider-groups",
      attributes: {
        name,
      },
      relationships: {},
    },
  };

  // Add relationships only if there are items
  if (providers.length > 0) {
    payload.data.relationships.providers = {
      data: providers,
    };
  }

  if (roles.length > 0) {
    payload.data.relationships.roles = {
      data: roles,
    };
  }

  const body = JSON.stringify(payload);

  try {
    const url = new URL(`${apiBaseUrl}/provider-groups`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body,
    });

    return handleApiResponse(response, "/manage-groups");
  } catch (error) {
    handleApiError(error);
  }
};

export const updateProviderGroup = async (
  providerGroupId: string,
  formData: FormData,
) => {
  const headers = await getAuthHeaders({ contentType: true });

  const name = formData.get("name") as string;
  const providersJson = formData.get("providers") as string;
  const rolesJson = formData.get("roles") as string;

  const providers = providersJson ? JSON.parse(providersJson) : null;
  const roles = rolesJson ? JSON.parse(rolesJson) : null;

  const payload: Partial<ManageGroupPayload> = {
    data: {
      type: "provider-groups",
      id: providerGroupId,
      attributes: name ? { name } : undefined,
      relationships: {},
    },
  };

  // Add relationships only if changes are detected
  if (providers) {
    payload.data!.relationships!.providers = { data: providers };
  }

  if (roles) {
    payload.data!.relationships!.roles = { data: roles };
  }

  try {
    const url = `${apiBaseUrl}/provider-groups/${providerGroupId}`;
    const response = await fetch(url, {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    return handleApiResponse(response, "/manage-groups");
  } catch (error) {
    handleApiError(error);
  }
};

export const deleteProviderGroup = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerGroupId = formData.get("id");

  if (!providerGroupId) {
    return {
      errors: [{ detail: "Provider Group ID is required." }],
    };
  }

  const url = new URL(`${apiBaseUrl}/provider-groups/${providerGroupId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.message || "Failed to delete the provider group",
        );
      } catch {
        throw new Error("Failed to delete the provider group");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/manage-groups");
    return data || { success: true };
  } catch (error) {
    console.error("Error deleting provider group:", error);
    const message = getErrorMessage(error);
    return { errors: [{ detail: message }] };
  }
};
