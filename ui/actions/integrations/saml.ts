"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { samlConfigFormSchema } from "@/types/formSchemas";

export const createSamlConfig = async (_prevState: any, formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = samlConfigFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        email_domain: formFieldErrors?.email_domain?.[0],
        metadata_xml: formFieldErrors?.metadata_xml?.[0],
      },
    };
  }

  const { email_domain, metadata_xml } = validatedData.data;

  try {
    const url = new URL(`${apiBaseUrl}/saml-config`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "saml-configurations",
          attributes: {
            email_domain: email_domain.trim(),
            metadata_xml: metadata_xml.trim(),
          },
        },
      }),
    });

    const result = await handleApiResponse(response, "/integrations", false);
    if (result.error) {
      return {
        errors: {
          general:
            result.error instanceof Error
              ? result.error.message
              : "Error creating SAML configuration. Please try again.",
        },
      };
    }

    return { success: "SAML configuration created successfully!" };
  } catch (error) {
    console.error("Error creating SAML config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating SAML configuration. Please try again.",
      },
    };
  }
};

export const updateSamlConfig = async (_prevState: any, formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = samlConfigFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        email_domain: formFieldErrors?.email_domain?.[0],
        metadata_xml: formFieldErrors?.metadata_xml?.[0],
      },
    };
  }

  const { email_domain, metadata_xml } = validatedData.data;

  try {
    const url = new URL(`${apiBaseUrl}/saml-config/${formDataObject.id}`);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "saml-configurations",
          id: formDataObject.id,
          attributes: {
            email_domain: email_domain.trim(),
            metadata_xml: metadata_xml.trim(),
          },
        },
      }),
    });

    await handleApiResponse(response, "/integrations", false);
    return { success: "SAML configuration updated successfully!" };
  } catch (error) {
    console.error("Error updating SAML config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating SAML configuration. Please try again.",
      },
    };
  }
};

export const getSamlConfig = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/saml-config`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching SAML config:", error);
    return undefined;
  }
};

export const deleteSamlConfig = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });

  try {
    const url = new URL(`${apiBaseUrl}/saml-config/${id}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete SAML config: ${response.statusText}`,
      );
    }

    revalidatePath("/integrations");
    return { success: "SAML configuration deleted successfully!" };
  } catch (error) {
    console.error("Error deleting SAML config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting SAML configuration. Please try again.",
      },
    };
  }
};

export const initiateSamlAuth = async (email: string) => {
  try {
    const response = await fetch(`${apiBaseUrl}/auth/saml/initiate/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
      },
      body: JSON.stringify({
        data: {
          type: "saml-initiate",
          attributes: {
            email_domain: email,
          },
        },
      }),
      redirect: "manual",
    });

    if (response.status === 302) {
      const location = response.headers.get("Location");

      if (location) {
        return {
          success: true,
          redirectUrl: location,
        };
      }
    }

    if (response.status === 403) {
      return {
        success: false,
        error: "Domain is not authorized for SAML authentication.",
      };
    }

    // Add error other error case:
    const errorData = await response.json().catch(() => ({}));
    return {
      success: false,
      error:
        errorData.errors?.[0]?.detail ||
        "An error occurred during SAML authentication.",
    };
  } catch (_error) {
    return {
      success: false,
      error: "Failed to connect to authentication service.",
    };
  }
};
