"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { isCloud } from "@/lib/shared/env";
import type { ApiResponse } from "@/types/components";
import {
  samlConfigFormSchema,
  samlConfigUpdateFormSchema,
} from "@/types/formSchemas";
import {
  SAML_CONFIGURATION_RESOURCE_TYPE,
  type SamlConfigurationActionState,
  type SamlConfigurationCreateRequestAttributes,
  type SamlConfigurationErrors,
  type SamlConfigurationUpdateRequestAttributes,
} from "@/types/saml";

const getSamlFormValues = (formData: FormData) => ({
  email_domain: formData.get("email_domain"),
  additional_email_domains: formData.getAll("additional_email_domains"),
  metadata_xml: formData.get("metadata_xml"),
});

const parseSamlCreateFormData = (formData: FormData) =>
  samlConfigFormSchema.safeParse(getSamlFormValues(formData));

const parseSamlUpdateFormData = (formData: FormData) =>
  samlConfigUpdateFormSchema.safeParse(getSamlFormValues(formData));

const mapApiErrorsToFields = (
  result: ApiResponse,
  fallback: string,
): SamlConfigurationErrors => {
  const errors: SamlConfigurationErrors = {};

  result.errors?.forEach((error) => {
    const pointer = error.source?.pointer;
    if (pointer?.includes("additional_email_domains")) {
      errors.additional_email_domains = error.detail;
    } else if (pointer?.includes("email_domain")) {
      errors.email_domain = error.detail;
    } else if (pointer?.includes("metadata_xml")) {
      errors.metadata_xml = error.detail;
    } else {
      errors.general = error.detail;
    }
  });

  if (Object.keys(errors).length === 0) {
    errors.general = result.error || fallback;
  }

  return errors;
};

const buildSamlRequestAttributes = (
  emailDomain: string,
  additionalEmailDomains: string[],
): SamlConfigurationUpdateRequestAttributes => ({
  email_domain: emailDomain,
  ...(isCloud() && {
    additional_email_domains: additionalEmailDomains,
  }),
});

const buildSamlCreateRequestAttributes = (
  emailDomain: string,
  additionalEmailDomains: string[],
  metadataXml: string,
): SamlConfigurationCreateRequestAttributes => ({
  ...buildSamlRequestAttributes(emailDomain, additionalEmailDomains),
  metadata_xml: metadataXml,
});

const buildSamlUpdateRequestAttributes = (
  emailDomain: string,
  additionalEmailDomains: string[],
  metadataXml?: string,
): SamlConfigurationUpdateRequestAttributes => ({
  ...buildSamlRequestAttributes(emailDomain, additionalEmailDomains),
  ...(metadataXml !== undefined && { metadata_xml: metadataXml }),
});

export const createSamlConfig = async (
  _prevState: SamlConfigurationActionState,
  formData: FormData,
): Promise<SamlConfigurationActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const validatedData = parseSamlCreateFormData(formData);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        email_domain: formFieldErrors?.email_domain?.[0],
        additional_email_domains:
          formFieldErrors?.additional_email_domains?.[0],
        metadata_xml: formFieldErrors?.metadata_xml?.[0],
      },
    };
  }

  const { email_domain, additional_email_domains, metadata_xml } =
    validatedData.data;

  try {
    const url = new URL(`${apiBaseUrl}/saml-config`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: SAML_CONFIGURATION_RESOURCE_TYPE,
          attributes: buildSamlCreateRequestAttributes(
            email_domain,
            additional_email_domains,
            metadata_xml,
          ),
        },
      }),
    });

    const result = (await handleApiResponse(
      response,
      "/profile",
      false,
    )) as ApiResponse;
    if (result.error) {
      return {
        errors: mapApiErrorsToFields(
          result,
          "Error creating SAML configuration. Please try again.",
        ),
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

export const updateSamlConfig = async (
  _prevState: SamlConfigurationActionState,
  formData: FormData,
): Promise<SamlConfigurationActionState> => {
  const id = String(formData.get("id") || "");
  if (!id) {
    return {
      errors: {
        general: "SAML configuration ID is required for update.",
      },
    };
  }

  const headers = await getAuthHeaders({ contentType: true });
  const validatedData = parseSamlUpdateFormData(formData);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        email_domain: formFieldErrors?.email_domain?.[0],
        additional_email_domains:
          formFieldErrors?.additional_email_domains?.[0],
        metadata_xml: formFieldErrors?.metadata_xml?.[0],
      },
    };
  }

  const { email_domain, additional_email_domains, metadata_xml } =
    validatedData.data;

  try {
    const url = new URL(`${apiBaseUrl}/saml-config/${id}`);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: SAML_CONFIGURATION_RESOURCE_TYPE,
          id,
          attributes: buildSamlUpdateRequestAttributes(
            email_domain,
            additional_email_domains,
            metadata_xml,
          ),
        },
      }),
    });

    const result = (await handleApiResponse(
      response,
      "/profile",
      false,
    )) as ApiResponse;
    if (result.error) {
      return {
        errors: mapApiErrorsToFields(
          result,
          "Error updating SAML configuration. Please try again.",
        ),
      };
    }
    return { success: "SAML configuration updated successfully!" };
  } catch (error) {
    console.error("Error updating SAML config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating SAML configuration. Please try again.",
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

    revalidatePath("/profile");
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

export const initiateSamlAuth = async (email: string, callbackUrl = "/") => {
  try {
    const attributes = {
      email_domain: email,
      ...(callbackUrl !== "/" && { callback_url: callbackUrl }),
    };

    const response = await fetch(`${apiBaseUrl}/auth/saml/initiate/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
      },
      body: JSON.stringify({
        data: {
          type: "saml-initiate",
          attributes,
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
