"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { parseStringify } from "@/lib";

export const getProviders = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  if (isNaN(Number(page)) || page < 1) redirect("/providers");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers?sort=-inserted_at`);

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
  const providerId = formData.get("id");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const providers = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.api+json",
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

export const checkConnectionProvider = async (formData: FormData) => {
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("id");

  const url = new URL(`${keyServer}/providers/${providerId}/connection`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        Accept: "application/vnd.api+json",
      },
    });
    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteProvider = async (formData: FormData) => {
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("id");
  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Accept: "application/vnd.api+json",
      },
    });
    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getErrorMessage = (error: unknown): string => {
  let message: string;

  if (error instanceof Error) {
    message = error.message;
  } else if (error && typeof error === "object" && "message" in error) {
    message = String(error.message);
  } else if (typeof error === "string") {
    message = error;
  } else {
    message = "Oops! Something went wrong.";
  }
  return message;
};
