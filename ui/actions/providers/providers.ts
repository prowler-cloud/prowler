"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  parseStringify,
  wait,
} from "@/lib";
import { ProvidersApiResponse, ProviderType } from "@/types/providers";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

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
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
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

  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);
  const providerType = formData.get(
    ProviderCredentialFields.PROVIDER_TYPE,
  ) as ProviderType;

  const isRole = formData.get(ProviderCredentialFields.ROLE_ARN) !== null;
  const isServiceAccount =
    formData.get(ProviderCredentialFields.SERVICE_ACCOUNT_KEY) !== null;

  let secret = {};
  let secretType = "static"; // Default to static credentials

  if (providerType === "aws") {
    if (isRole) {
      // Role-based configuration for AWS
      secretType = "role";
      secret = {
        [ProviderCredentialFields.ROLE_ARN]: formData.get(
          ProviderCredentialFields.ROLE_ARN,
        ),
        [ProviderCredentialFields.EXTERNAL_ID]: formData.get(
          ProviderCredentialFields.EXTERNAL_ID,
        ),
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]:
          formData.get(ProviderCredentialFields.AWS_ACCESS_KEY_ID) || undefined,
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]:
          formData.get(ProviderCredentialFields.AWS_SECRET_ACCESS_KEY) ||
          undefined,
        [ProviderCredentialFields.AWS_SESSION_TOKEN]:
          formData.get(ProviderCredentialFields.AWS_SESSION_TOKEN) || undefined,
        session_duration:
          parseInt(
            formData.get(ProviderCredentialFields.SESSION_DURATION) as string,
            10,
          ) || 3600,
        [ProviderCredentialFields.ROLE_SESSION_NAME]:
          formData.get(ProviderCredentialFields.ROLE_SESSION_NAME) || undefined,
      };
    } else {
      // Static credentials configuration for AWS
      secret = {
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: formData.get(
          ProviderCredentialFields.AWS_ACCESS_KEY_ID,
        ),
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: formData.get(
          ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
        ),
        [ProviderCredentialFields.AWS_SESSION_TOKEN]:
          formData.get(ProviderCredentialFields.AWS_SESSION_TOKEN) || undefined,
      };
    }
  } else if (providerType === "azure") {
    // Static credentials configuration for Azure
    secret = {
      [ProviderCredentialFields.CLIENT_ID]: formData.get(
        ProviderCredentialFields.CLIENT_ID,
      ),
      [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
        ProviderCredentialFields.CLIENT_SECRET,
      ),
      [ProviderCredentialFields.TENANT_ID]: formData.get(
        ProviderCredentialFields.TENANT_ID,
      ),
    };
  } else if (providerType === "m365") {
    // Static credentials configuration for M365
    secret = {
      [ProviderCredentialFields.CLIENT_ID]: formData.get(
        ProviderCredentialFields.CLIENT_ID,
      ),
      [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
        ProviderCredentialFields.CLIENT_SECRET,
      ),
      [ProviderCredentialFields.TENANT_ID]: formData.get(
        ProviderCredentialFields.TENANT_ID,
      ),
      [ProviderCredentialFields.USER]: formData.get(
        ProviderCredentialFields.USER,
      ),
      [ProviderCredentialFields.PASSWORD]: formData.get(
        ProviderCredentialFields.PASSWORD,
      ),
    };
  } else if (providerType === "gcp") {
    if (isServiceAccount) {
      // Service account configuration for GCP
      secretType = "service_account";
      const serviceAccountKeyRaw = formData.get(
        ProviderCredentialFields.SERVICE_ACCOUNT_KEY,
      ) as string;

      try {
        const serviceAccountKey = JSON.parse(serviceAccountKeyRaw);
        secret = {
          service_account_key: serviceAccountKey,
        };
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error("error", error);
      }
    } else {
      // Static credentials configuration for GCP
      secret = {
        [ProviderCredentialFields.CLIENT_ID]: formData.get(
          ProviderCredentialFields.CLIENT_ID,
        ),
        [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
          ProviderCredentialFields.CLIENT_SECRET,
        ),
        [ProviderCredentialFields.REFRESH_TOKEN]: formData.get(
          ProviderCredentialFields.REFRESH_TOKEN,
        ),
      };
    }
  } else if (providerType === "kubernetes") {
    // Static credentials configuration for Kubernetes
    secret = {
      [ProviderCredentialFields.KUBECONFIG_CONTENT]: formData.get(
        ProviderCredentialFields.KUBECONFIG_CONTENT,
      ),
    };
  }
  const bodyData = {
    data: {
      type: "provider-secrets",
      attributes: {
        secret_type: secretType,
        secret,
      },
      relationships: {
        provider: {
          data: {
            id: providerId,
            type: "providers",
          },
        },
      },
    },
  };

  try {
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

export const updateCredentialsProvider = async (
  credentialsId: string,
  formData: FormData,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/providers/secrets/${credentialsId}`);

  const providerType = formData.get("providerType") as ProviderType;

  const isRole = formData.get("role_arn") !== null;
  const isServiceAccount = formData.get("service_account_key") !== null;

  let secret = {};

  if (providerType === "aws") {
    if (isRole) {
      // Role-based configuration for AWS
      secret = {
        [ProviderCredentialFields.ROLE_ARN]: formData.get(
          ProviderCredentialFields.ROLE_ARN,
        ),
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]:
          formData.get(ProviderCredentialFields.AWS_ACCESS_KEY_ID) || undefined,
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]:
          formData.get(ProviderCredentialFields.AWS_SECRET_ACCESS_KEY) ||
          undefined,
        [ProviderCredentialFields.AWS_SESSION_TOKEN]:
          formData.get(ProviderCredentialFields.AWS_SESSION_TOKEN) || undefined,
        [ProviderCredentialFields.SESSION_DURATION]:
          parseInt(
            formData.get(ProviderCredentialFields.SESSION_DURATION) as string,
            10,
          ) || 3600,
        [ProviderCredentialFields.EXTERNAL_ID]:
          formData.get(ProviderCredentialFields.EXTERNAL_ID) || undefined,
        [ProviderCredentialFields.ROLE_SESSION_NAME]:
          formData.get(ProviderCredentialFields.ROLE_SESSION_NAME) || undefined,
      };
    } else {
      // Static credentials configuration for AWS
      secret = {
        [ProviderCredentialFields.AWS_ACCESS_KEY_ID]: formData.get(
          ProviderCredentialFields.AWS_ACCESS_KEY_ID,
        ),
        [ProviderCredentialFields.AWS_SECRET_ACCESS_KEY]: formData.get(
          ProviderCredentialFields.AWS_SECRET_ACCESS_KEY,
        ),
        [ProviderCredentialFields.AWS_SESSION_TOKEN]:
          formData.get(ProviderCredentialFields.AWS_SESSION_TOKEN) || undefined,
      };
    }
  } else if (providerType === "azure") {
    // Static credentials configuration for Azure
    secret = {
      [ProviderCredentialFields.CLIENT_ID]: formData.get(
        ProviderCredentialFields.CLIENT_ID,
      ),
      [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
        ProviderCredentialFields.CLIENT_SECRET,
      ),
      [ProviderCredentialFields.TENANT_ID]: formData.get(
        ProviderCredentialFields.TENANT_ID,
      ),
    };
  } else if (providerType === "m365") {
    // Static credentials configuration for M365
    secret = {
      [ProviderCredentialFields.CLIENT_ID]: formData.get(
        ProviderCredentialFields.CLIENT_ID,
      ),
      [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
        ProviderCredentialFields.CLIENT_SECRET,
      ),
      [ProviderCredentialFields.TENANT_ID]: formData.get(
        ProviderCredentialFields.TENANT_ID,
      ),
      [ProviderCredentialFields.USER]: formData.get(
        ProviderCredentialFields.USER,
      ),
      password: formData.get(ProviderCredentialFields.PASSWORD),
    };
  } else if (providerType === "gcp") {
    if (isServiceAccount) {
      // Service account configuration for GCP
      const serviceAccountKeyRaw = formData.get(
        ProviderCredentialFields.SERVICE_ACCOUNT_KEY,
      ) as string;

      try {
        // Parse the service account key as JSON
        const serviceAccountKey = JSON.parse(serviceAccountKeyRaw);
        secret = {
          service_account_key: serviceAccountKey,
        };
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error("error", error);
      }
    } else {
      // Static credentials configuration for GCP
      secret = {
        [ProviderCredentialFields.CLIENT_ID]: formData.get(
          ProviderCredentialFields.CLIENT_ID,
        ),
        [ProviderCredentialFields.CLIENT_SECRET]: formData.get(
          ProviderCredentialFields.CLIENT_SECRET,
        ),
        [ProviderCredentialFields.REFRESH_TOKEN]: formData.get(
          ProviderCredentialFields.REFRESH_TOKEN,
        ),
      };
    }
  } else if (providerType === "kubernetes") {
    // Static credentials configuration for Kubernetes
    secret = {
      [ProviderCredentialFields.KUBECONFIG_CONTENT]: formData.get(
        ProviderCredentialFields.KUBECONFIG_CONTENT,
      ),
    };
  }

  const bodyData = {
    data: {
      type: "provider-secrets",
      id: credentialsId,
      attributes: {
        secret,
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    const data = await response.json();

    if (!response.ok) {
      // Return the API errors structure for proper handling in the UI
      return parseStringify(data);
    }

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

export const checkConnectionProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });

  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);

  const url = new URL(`${apiBaseUrl}/providers/${providerId}/connection`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });
    const data = await response.json();
    await wait(2000);
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
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
