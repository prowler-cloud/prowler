"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  parseStringify,
} from "@/lib";

export const getRoles = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/roles");

  const url = new URL(`${apiBaseUrl}/roles`);

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
    const roles = await fetch(url.toString(), {
      headers,
    });
    const data = await roles.json();
    const parsedData = parseStringify(data);
    revalidatePath("/roles");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching roles:", error);
    return undefined;
  }
};

export const getRoleInfoById = async (roleId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/roles/${roleId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch role info: ${response.statusText}`);
    }

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const addRole = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const name = formData.get("name") as string;
  const groups = formData.getAll("groups[]") as string[];

  const payload: any = {
    data: {
      type: "roles",
      attributes: {
        name,
        manage_users: formData.get("manage_users") === "true",
        manage_providers: formData.get("manage_providers") === "true",
        manage_scans: formData.get("manage_scans") === "true",
        manage_account: formData.get("manage_account") === "true",
        // TODO: Add back when we have integrations ready
        // manage_integrations: formData.get("manage_integrations") === "true",
        unlimited_visibility: formData.get("unlimited_visibility") === "true",
      },
      relationships: {},
    },
  };

  // Conditionally include manage_billing for cloud environment
  if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
    payload.data.attributes.manage_billing =
      formData.get("manage_billing") === "true";
  }

  // Add provider groups relationships only if there are items
  if (groups.length > 0) {
    payload.data.relationships.provider_groups = {
      data: groups.map((groupId: string) => ({
        type: "provider-groups",
        id: groupId,
      })),
    };
  }

  const body = JSON.stringify(payload);

  try {
    const url = new URL(`${apiBaseUrl}/roles`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body,
    });

    const data = await response.json();
    revalidatePath("/roles");
    return data;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error during API call:", error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateRole = async (formData: FormData, roleId: string) => {
  const headers = await getAuthHeaders({ contentType: true });

  const name = formData.get("name") as string;
  const groups = formData.getAll("groups[]") as string[];

  const payload: any = {
    data: {
      type: "roles",
      id: roleId,
      attributes: {
        ...(name && { name }), // Include name only if provided
        manage_users: formData.get("manage_users") === "true",
        manage_providers: formData.get("manage_providers") === "true",
        manage_account: formData.get("manage_account") === "true",
        manage_scans: formData.get("manage_scans") === "true",
        // TODO: Add back when we have integrations ready
        // manage_integrations: formData.get("manage_integrations") === "true",
        unlimited_visibility: formData.get("unlimited_visibility") === "true",
      },
      relationships: {},
    },
  };

  // Conditionally include manage_billing for cloud environments
  if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true") {
    payload.data.attributes.manage_billing =
      formData.get("manage_billing") === "true";
  }

  // Add provider groups relationships only if there are items
  if (groups.length > 0) {
    payload.data.relationships.provider_groups = {
      data: groups.map((groupId: string) => ({
        type: "provider-groups",
        id: groupId,
      })),
    };
  }

  const body = JSON.stringify(payload);

  try {
    const url = new URL(`${apiBaseUrl}/roles/${roleId}`);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body,
    });

    const data = await response.json();
    revalidatePath("/roles");
    return data;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error during API call:", error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteRole = async (roleId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/roles/${roleId}`);
  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData?.message || "Failed to delete the role");
      } catch {
        throw new Error("Failed to delete the role");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/roles");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error deleting role:", error);
    return { error: getErrorMessage(error) };
  }
};
