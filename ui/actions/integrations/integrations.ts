"use server";

import { revalidatePath } from "next/cache";

import {
  apiBaseUrl,
  getAuthHeaders,
  handleApiError,
  parseStringify,
} from "@/lib";

export const getIntegrations = async (searchParams?: URLSearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  if (searchParams) {
    searchParams.forEach((value, key) => {
      url.searchParams.append(key, value);
    });
  }

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data = await response.json();
      return parseStringify(data);
    }

    console.error(`Failed to fetch integrations: ${response.statusText}`);
    return { data: [], meta: { pagination: { count: 0 } } };
  } catch (error) {
    console.error("Error fetching integrations:", error);
    return { data: [], meta: { pagination: { count: 0 } } };
  }
};

export const getIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data = await response.json();
      return parseStringify(data);
    }

    console.error(`Failed to fetch integration: ${response.statusText}`);
    return null;
  } catch (error) {
    console.error("Error fetching integration:", error);
    return null;
  }
};

export const createIntegration = async (
  formData: FormData,
): Promise<{ success: string; testConnection?: any } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = JSON.parse(formData.get("configuration") as string);
    const credentials = JSON.parse(formData.get("credentials") as string);
    const providers = JSON.parse(formData.get("providers") as string);

    const integrationData = {
      data: {
        type: "integrations",
        attributes: { integration_type, configuration, credentials },
        relationships: {
          providers: {
            data: providers.map((providerId: string) => ({
              id: providerId,
              type: "providers",
            })),
          },
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(integrationData),
    });

    if (response.ok) {
      const responseData = await response.json();
      const integrationId = responseData.data.id;

      const testResult = await testIntegrationConnection(integrationId);

      return {
        success: "Integration created successfully!",
        testConnection: testResult,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to create S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateIntegration = async (id: string, formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = JSON.parse(formData.get("configuration") as string);
    const credentials = formData.get("credentials")
      ? JSON.parse(formData.get("credentials") as string)
      : undefined;
    const providers = formData.get("providers")
      ? JSON.parse(formData.get("providers") as string)
      : undefined;

    const integrationData: any = {
      data: {
        type: "integrations",
        id,
        attributes: { integration_type, configuration },
      },
    };

    if (credentials) {
      integrationData.data.attributes.credentials = credentials;
    }

    if (providers) {
      integrationData.data.relationships = {
        providers: {
          data: providers.map((providerId: string) => ({
            id: providerId,
            type: "providers",
          })),
        },
      };
    }

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(integrationData),
    });

    if (response.ok) {
      // Automatically test the connection after updating
      const testResult = await testIntegrationConnection(id);

      return {
        success: "Integration updated successfully!",
        testConnection: testResult,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to update S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), { method: "DELETE", headers });

    if (response.ok) {
      revalidatePath("/integrations/s3");
      return { success: "Integration deleted successfully!" };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to delete S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const testIntegrationConnection = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}/connection`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (response.ok) {
      const data = await response.json();
      revalidatePath("/integrations/s3");

      return {
        success: "Connection test started successfully!",
        data: parseStringify(data),
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to test S3 integration connection: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};
