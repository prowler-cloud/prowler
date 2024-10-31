"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify, wait } from "@/lib";

export const getProviders = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/providers");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers`);

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
    const providers = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    revalidatePath("/providers");
    return parsedData;
  } catch (error) {
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

export const getProvider = async (formData: FormData) => {
  const session = await auth();
  const providerId = formData.get("id");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const providers = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateProvider = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("providerId");
  const providerAlias = formData.get("alias");

  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify({
        data: {
          type: "Provider",
          id: providerId,
          attributes: {
            alias: providerAlias,
          },
        },
      }),
    });
    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const addProvider = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerType = formData.get("providerType");
  const providerId = formData.get("providerId");
  const providerAlias = formData.get("providerAlias");

  const url = new URL(`${keyServer}/providers`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify({
        data: {
          type: "Provider",
          attributes: {
            provider: providerType,
            uid: providerId,
            alias: providerAlias,
          },
        },
      }),
    });
    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const addCredentialsProvider = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers/secrets`);

  const secretName = formData.get("secretName");
  const providerId = formData.get("providerId");
  const providerType = formData.get("providerType");

  let secret = {};

  if (providerType === "aws") {
    secret = {
      aws_access_key_id: formData.get("aws_access_key_id"),
      aws_secret_access_key: formData.get("aws_secret_access_key"),
      aws_session_token: formData.get("aws_session_token") || undefined,
    };
  } else if (providerType === "azure") {
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      tenant_id: formData.get("tenant_id"),
    };
  } else if (providerType === "gcp") {
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      refresh_token: formData.get("refresh_token"),
    };
  }

  const bodyData = {
    data: {
      type: "ProviderSecret",
      attributes: {
        secret_type: "static",
        secret,
        name: secretName,
      },
      relationships: {
        provider: {
          data: {
            id: providerId,
            type: "Provider",
          },
        },
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
      body: JSON.stringify(bodyData),
    });
    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const checkConnectionProvider = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("id");

  const url = new URL(`${keyServer}/providers/${providerId}/connection`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    await wait(1000);
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteProvider = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("id");
  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    await wait(1000);
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
