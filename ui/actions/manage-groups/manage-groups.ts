"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify, wait } from "@/lib";
import { ManageGroupPayload, ProviderGroupsResponse } from "@/types/components";

export const getProviderGroups = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string | number>;
}): Promise<ProviderGroupsResponse | undefined> => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/manage-groups");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/provider-groups`);

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
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Error fetching provider groups: ${response.statusText}`);
    }

    const data: ProviderGroupsResponse = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/manage-groups");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching provider groups:", error);
    return undefined;
  }
};

export const getProviderGroupInfoById = async (providerGroupId: string) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/provider-groups/${providerGroupId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch provider group info: ${response.statusText}`,
      );
    }

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const createProviderGroup = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

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
    const url = new URL(`${keyServer}/provider-groups`);
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
    revalidatePath("/manage-groups");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateProviderGroup = async (
  providerGroupId: string,
  formData: FormData,
) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

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
    const url = `${keyServer}/provider-groups/${providerGroupId}`;
    const response = await fetch(url, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(
        `Failed to update provider group: ${response.status} ${response.statusText}`,
      );
    }

    const data = await response.json();
    revalidatePath("/manage-groups");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteProviderGroup = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerGroupId = formData.get("id");
  const url = new URL(`${keyServer}/provider-groups/${providerGroupId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    await wait(2000);
    revalidatePath("/manage-groups");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
