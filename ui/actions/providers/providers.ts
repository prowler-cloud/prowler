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

export const getProviders = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers");

  const url = new URL(`${apiBaseUrl}/providers?include=provider_groups`);

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

  const providerId = formData.get("providerId");
  const providerAlias = formData.get("alias");

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

  const providerType = formData.get("providerType") as string;
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

  const secretName = formData.get("secretName");
  const providerId = formData.get("providerId");
  const providerType = formData.get("providerType");

  const isRole = formData.get("role_arn") !== null;

  let secret = {};
  let secretType = "static"; // Default to static credentials

  if (providerType === "aws") {
    if (isRole) {
      // Role-based configuration for AWS
      secretType = "role";
      secret = {
        role_arn: formData.get("role_arn"),
        external_id: formData.get("external_id"),
        aws_access_key_id: formData.get("aws_access_key_id") || undefined,
        aws_secret_access_key:
          formData.get("aws_secret_access_key") || undefined,
        aws_session_token: formData.get("aws_session_token") || undefined,
        session_duration:
          parseInt(formData.get("session_duration") as string, 10) || 3600,
        role_session_name: formData.get("role_session_name") || undefined,
      };
    } else {
      // Static credentials configuration for AWS
      secret = {
        aws_access_key_id: formData.get("aws_access_key_id"),
        aws_secret_access_key: formData.get("aws_secret_access_key"),
        aws_session_token: formData.get("aws_session_token") || undefined,
      };
    }
  } else if (providerType === "azure") {
    // Static credentials configuration for Azure
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      tenant_id: formData.get("tenant_id"),
    };
  } else if (providerType === "m365") {
    // Static credentials configuration for M365
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      tenant_id: formData.get("tenant_id"),
      user: formData.get("user"),
      encrypted_password: formData.get("encrypted_password"),
    };
  } else if (providerType === "gcp") {
    // Static credentials configuration for GCP
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      refresh_token: formData.get("refresh_token"),
    };
  } else if (providerType === "kubernetes") {
    // Static credentials configuration for Kubernetes
    secret = {
      kubeconfig_content: formData.get("kubeconfig_content"),
    };
  }

  const bodyData = {
    data: {
      type: "provider-secrets",
      attributes: {
        secret_type: secretType,
        secret,
        name: secretName,
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

  const secretName = formData.get("secretName");
  const providerType = formData.get("providerType");

  const isRole = formData.get("role_arn") !== null;

  let secret = {};

  if (providerType === "aws") {
    if (isRole) {
      // Role-based configuration for AWS
      secret = {
        role_arn: formData.get("role_arn"),
        aws_access_key_id: formData.get("aws_access_key_id") || undefined,
        aws_secret_access_key:
          formData.get("aws_secret_access_key") || undefined,
        aws_session_token: formData.get("aws_session_token") || undefined,
        session_duration:
          parseInt(formData.get("session_duration") as string, 10) || 3600,
        external_id: formData.get("external_id") || undefined,
        role_session_name: formData.get("role_session_name") || undefined,
      };
    } else {
      // Static credentials configuration for AWS
      secret = {
        aws_access_key_id: formData.get("aws_access_key_id"),
        aws_secret_access_key: formData.get("aws_secret_access_key"),
        aws_session_token: formData.get("aws_session_token") || undefined,
      };
    }
  } else if (providerType === "azure") {
    // Static credentials configuration for Azure
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      tenant_id: formData.get("tenant_id"),
    };
  } else if (providerType === "m365") {
    // Static credentials configuration for M365
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      tenant_id: formData.get("tenant_id"),
      user: formData.get("user"),
      encrypted_password: formData.get("encrypted_password"),
    };
  } else if (providerType === "gcp") {
    // Static credentials configuration for GCP
    secret = {
      client_id: formData.get("client_id"),
      client_secret: formData.get("client_secret"),
      refresh_token: formData.get("refresh_token"),
    };
  } else if (providerType === "kubernetes") {
    // Static credentials configuration for Kubernetes
    secret = {
      kubeconfig_content: formData.get("kubeconfig_content"),
    };
  }

  const bodyData = {
    data: {
      type: "provider-secrets",
      id: credentialsId,
      attributes: {
        name: secretName,
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

    if (!response.ok) {
      throw new Error(`Failed to update credentials: ${response.statusText}`);
    }

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

export const checkConnectionProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });

  const providerId = formData.get("providerId");

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
  const providerId = formData.get("id");

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
