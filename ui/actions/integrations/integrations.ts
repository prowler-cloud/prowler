"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";

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
    const integration_type = formData.get("integration_type") as string;
    const configuration = JSON.parse(formData.get("configuration") as string);
    const credentials = JSON.parse(formData.get("credentials") as string);
    const providers = JSON.parse(formData.get("providers") as string);

    const integrationData = {
      data: {
        type: "integrations",
        attributes: {
          integration_type,
          configuration,
          credentials, // credentials should be at attributes level, not inside configuration
        },
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
      revalidatePath("/integrations/s3");
      return { success: "Integration created successfully!" };
    } else {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: {
          general:
            errorData.errors?.[0]?.detail ||
            `Failed to create integration: ${response.statusText}`,
        },
      };
    }
  } catch (error) {
    console.error("Error creating integration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating integration. Please try again.",
      },
    };
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
        attributes: {
          integration_type,
          configuration,
        },
      },
    };

    // Add credentials if provided (they might not be included in updates for security)
    if (credentials) {
      integrationData.data.attributes.credentials = credentials;
    }

    // Add relationships if providers are specified
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
      revalidatePath("/integrations/s3");
      return { success: "Integration updated successfully!" };
    } else {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: {
          general:
            errorData.errors?.[0]?.detail ||
            `Failed to update integration: ${response.statusText}`,
        },
      };
    }
  } catch (error) {
    console.error("Error updating integration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating integration. Please try again.",
      },
    };
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

    revalidatePath("/integrations/s3");
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
