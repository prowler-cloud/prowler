"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, getFormValue, wait } from "@/lib";
import { buildSecretConfig } from "@/lib/provider-credentials/build-crendentials";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
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
    const response = await fetch(url.toString(), {
      headers,
    });

    return (await handleApiResponse(response)) as
      | ProvidersApiResponse
      | undefined;
  } catch (error) {
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

/**
 * Fetches all providers by iterating through all pages.
 * This is useful when you need the complete list of providers without pagination limits,
 * such as for dropdown menus or selection lists.
 */
export const getAllProviders = async ({
  query = "",
  sort = "",
  filters = {},
}: {
  query?: string;
  sort?: string;
  filters?: Record<string, unknown>;
} = {}): Promise<ProvidersApiResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const pageSize = 100; // Use larger page size to minimize API calls
  const maxPages = 50; // Safety limit: 50 pages × 100 = 5000 providers max
  let currentPage = 1;
  const allProviders: ProvidersApiResponse["data"] = [];
  let lastResponse: ProvidersApiResponse | undefined;
  let hasMorePages = true;

  try {
    while (hasMorePages && currentPage <= maxPages) {
      const url = new URL(`${apiBaseUrl}/providers?include=provider_groups`);
      url.searchParams.append("page[number]", currentPage.toString());
      url.searchParams.append("page[size]", pageSize.toString());

      if (query) url.searchParams.append("filter[search]", query);
      if (sort) url.searchParams.append("sort", sort);

      Object.entries(filters).forEach(([key, value]) => {
        if (key !== "filter[search]") {
          url.searchParams.append(key, String(value));
        }
      });

      const response = await fetch(url.toString(), { headers });
      const data = (await handleApiResponse(response)) as
        | ProvidersApiResponse
        | undefined;

      if (!data?.data || data.data.length === 0) {
        hasMorePages = false;
        continue;
      }

      allProviders.push(...data.data);
      lastResponse = data;

      // Check if we've fetched all pages
      const totalPages = data.meta?.pagination?.pages || 1;
      if (currentPage >= totalPages) {
        hasMorePages = false;
      } else {
        currentPage++;
      }
    }

    // Return combined response with all providers
    if (lastResponse) {
      return {
        ...lastResponse,
        data: allProviders,
        meta: {
          ...lastResponse.meta,
          pagination: {
            ...lastResponse.meta?.pagination,
            page: 1,
            pages: 1,
            count: allProviders.length,
          },
        },
      };
    }

    return undefined;
  } catch (error) {
    console.error("Error fetching all providers:", error);
    return undefined;
  }
};

export const getProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get("id");

  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
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

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
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
  const providerUid = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_UID,
  ) as string | undefined;

  try {
    // For IaC provider, fetch the provider data to get the repository URL from uid
    if (providerType === "iac") {
      const providerUrl = new URL(`${apiBaseUrl}/providers/${providerId}`);
      const providerResponse = await fetch(providerUrl.toString(), {
        headers: await getAuthHeaders({ contentType: false }),
      });

      if (providerResponse.ok) {
        const providerData = await providerResponse.json();
        const providerUid = providerData?.data?.attributes?.uid;

        // Add the repository URL to formData using the provider's uid
        if (providerUid) {
          formData.append(ProviderCredentialFields.REPOSITORY_URL, providerUid);
        }
      }
    }

    const { secretType, secret } = buildSecretConfig(
      formData,
      providerType,
      providerUid,
    );

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
    const { secretType, secret } = buildSecretConfig(formData, providerType);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "provider-secrets",
          id: credentialsId,
          attributes: { secret_type: secretType, secret },
        },
      }),
    });

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
    handleApiError(error);
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
    handleApiError(error);
  }
};
