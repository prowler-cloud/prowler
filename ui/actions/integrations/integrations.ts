"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import {
  handleApiError,
  handleApiResponse,
} from "@/lib/provider-credentials/build-crendentials";

export const getIntegrations = async (searchParams?: URLSearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  if (searchParams) {
    searchParams.forEach((value, key) => {
      url.searchParams.append(key, value);
    });
  }

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch integrations: ${response.statusText}`);
    }

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    console.error("Error fetching integrations:", error);
    return { data: [], meta: { pagination: { count: 0 } } };
  }
};

export const getIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch integration: ${response.statusText}`);
    }

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    console.error("Error fetching integration:", error);
    return null;
  }
};

export const createIntegration = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations`);

  try {
    const integrationData = {
      data: {
        type: "integrations",
        attributes: {
          integration_type: formData.get("integration_type"),
          configuration: JSON.parse(formData.get("configuration") as string),
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(integrationData),
    });

    return handleApiResponse(response, "/integrations");
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateIntegration = async (id: string, formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const integrationData = {
      data: {
        type: "integrations",
        id,
        attributes: {
          integration_type: formData.get("integration_type"),
          configuration: JSON.parse(formData.get("configuration") as string),
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(integrationData),
    });

    return handleApiResponse(response, "/integrations");
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete integration: ${response.statusText}`,
      );
    }

    revalidatePath("/integrations");
    return { success: "Integration deleted successfully!" };
  } catch (error) {
    console.error("Error deleting integration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting integration. Please try again.",
      },
    };
  }
};

export const testIntegrationConnection = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}/connection`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to test connection: ${response.statusText}`,
      );
    }

    const data = await response.json();
    return {
      success: "Connection test started successfully!",
      data: parseStringify(data),
    };
  } catch (error) {
    console.error("Error testing integration connection:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error testing connection. Please try again.",
      },
    };
  }
};
