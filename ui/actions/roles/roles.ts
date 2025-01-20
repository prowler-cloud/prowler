"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

export const getRoles = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/roles");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/roles`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const invitations = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await invitations.json();
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/roles/${roleId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

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

  // Conditionally include manage_account and manage_billing for cloud environment
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
    const url = new URL(`${keyServer}/roles`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

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

  // Conditionally include manage_account and manage_billing for cloud environments
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
    const url = new URL(`${keyServer}/roles/${roleId}`);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const url = new URL(`${keyServer}/roles/${roleId}`);
  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData?.message || "Failed to delete the role");
    }

    const data = await response.json();
    revalidatePath("/roles");
    return data;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
