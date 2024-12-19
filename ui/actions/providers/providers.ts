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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerType = formData.get("providerType") as string;
  const providerUid = formData.get("providerUid") as string;
  const providerAlias = formData.get("providerAlias") as string;

  const url = new URL(`${keyServer}/providers`);

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
    // eslint-disable-next-line no-console
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

  const isRole = formData.get("role_arn") !== null;

  let secret = {};
  let secretType = "static"; // Default to static credentials

  if (providerType === "aws") {
    if (isRole) {
      // Role-based configuration for AWS
      secretType = "role";
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers/secrets/${credentialsId}`);

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
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("providerId");

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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/providers/secrets/${secretId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
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
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const providerId = formData.get("id");
  const url = new URL(`${keyServer}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
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
