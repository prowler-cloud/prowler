"use server";

import { revalidatePath } from "next/cache";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify } from "@/lib";

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
    revalidatePath("/providers/manage-groups");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
