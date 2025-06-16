"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  getFormValue,
  parseStringify,
  wait,
} from "@/lib";
import {
  buildSecretConfig,
  buildUpdateSecretConfig,
  handleApiError,
  handleApiResponse,
} from "@/lib/provider-credentials/build-crendentials";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { ProvidersApiResponse, ProviderType } from "@/types/providers";

export const getProviders = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}): Promise<ProvidersApiResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers");

  const url = new URL(`${apiBaseUrl}/providers?include=provider_groups`);

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
    const providers = await fetch(url.toString(), {
      headers,
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    revalidatePath("/providers");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

export const getProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get("id");

  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const providers = await fetch(url.toString(), {
      headers,
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
  const headers = await getAuthHeaders({ contentType: true });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);
  const providerAlias = formData.get(ProviderCredentialFields.PROVIDER_ALIAS);
  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "providers",
          id: providerId,
          attributes: { alias: providerAlias },
        },
      }),
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const addProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const providerType = formData.get("providerType") as ProviderType;
  const providerUid = formData.get("providerUid") as string;
  const providerAlias = formData.get("providerAlias") as string;

  const url = new URL(`${apiBaseUrl}/providers`);

  try {
    const bodyData = {
      data: {
        type: "providers",
        attributes: {
          provider: providerType,
          uid: providerUid,
          ...(providerAlias?.trim() && { alias: providerAlias.trim() }),
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bodyData),
    });

    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const addCredentialsProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/providers/secrets`);

  const providerId = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_ID,
  );
  const providerType = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_TYPE,
  ) as ProviderType;

  try {
    const { secretType, secret } = buildSecretConfig(formData, providerType);

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "provider-secrets",
          attributes: { secret_type: secretType, secret },
          relationships: {
            provider: {
              data: { id: providerId, type: "providers" },
            },
          },
        },
      }),
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateCredentialsProvider = async (
  credentialsId: string,
  formData: FormData,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/providers/secrets/${credentialsId}`);
  const providerType = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_TYPE,
  ) as ProviderType;

  try {
    const secret = buildUpdateSecretConfig(formData, providerType);

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "provider-secrets",
          id: credentialsId,
          attributes: { secret },
        },
      }),
    });

    if (!response.ok) {
      const data = await response.json();
      return parseStringify(data); // Return API errors for UI handling
    }

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const checkConnectionProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);
  const url = new URL(`${apiBaseUrl}/providers/${providerId}/connection`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });
    await wait(2000);
    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteCredentials = async (secretId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (!secretId) {
    return { error: "Secret ID is required" };
  }

  const url = new URL(`${apiBaseUrl}/providers/secrets/${secretId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.message || "Failed to delete the credentials",
        );
      } catch {
        throw new Error("Failed to delete the credentials");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/providers");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error deleting credentials:", error);
    return { error: getErrorMessage(error) };
  }
};

export const deleteProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);

  if (!providerId) {
    return { error: "Provider ID is required" };
  }

  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData?.message || "Failed to delete the provider");
      } catch {
        throw new Error("Failed to delete the provider");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/providers");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error deleting provider:", error);
    return { error: getErrorMessage(error) };
  }
};
