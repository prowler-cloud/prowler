"use server";

import yaml from "js-yaml";
import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { scanConfigurationFormSchema } from "@/types/formSchemas";
import {
  DeleteScanConfigurationActionState,
  ScanConfigurationActionState,
  ScanConfigurationData,
  ScanConfigurationErrors,
  ScanConfigurationRequestBody,
} from "@/types/scan-configurations";

const SCAN_CONFIGURATION_PATH = "/scans/config";

// Scan Configuration IDs are UUIDs. Validate before interpolating into request
// URLs so a malformed/crafted value can't inject path segments (SSRF / path
// injection).
const scanConfigurationIdSchema = z.uuid();

// Provider IDs are UUIDs too. Validate the whole array at the action boundary so
// a malformed/crafted id fails here instead of relying on API-side validation.
const providerIdsSchema = z.array(z.uuid());

const parseConfiguration = (value: string): Record<string, unknown> => {
  // Backend (YamlOrJsonField) accepts either a YAML string or a JSON object.
  // We parse client-side so failures surface as form errors, not 500s.
  const parsed = yaml.load(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Configuration must be a mapping with provider sections.");
  }
  return parsed as Record<string, unknown>;
};

const collectProviderIds = (formData: FormData): string[] => {
  return formData
    .getAll("provider_ids")
    .map((v) => String(v))
    .filter(Boolean);
};

interface ApiErrorSource {
  pointer?: string;
}

interface ApiError {
  detail?: string;
  title?: string;
  source?: ApiErrorSource;
}

// Route each JSON:API error to the matching form field via its `source.pointer`
// so it renders inline next to the offending input. Only errors we can't anchor
// to a field fall back to `general` (surfaced as a toast). Shared by create and
// update so both flows present validation errors identically — otherwise a
// config error shows inline on create but as a toast on update.
const mapApiErrorsToFields = (
  errorData: { errors?: ApiError[]; message?: string } | null | undefined,
  fallbackMessage: string,
): ScanConfigurationErrors => {
  const apiErrors = Array.isArray(errorData?.errors) ? errorData!.errors! : [];

  if (apiErrors.length === 0) {
    return { general: errorData?.message || fallbackMessage };
  }

  const errors: ScanConfigurationErrors = {};
  const append = (key: keyof ScanConfigurationErrors, detail: string) => {
    errors[key] = errors[key] ? `${errors[key]}\n${detail}` : detail;
  };

  for (const err of apiErrors) {
    const detail = err?.detail || err?.title || fallbackMessage;
    const pointer = err?.source?.pointer;
    if (pointer?.includes("name")) append("name", detail);
    else if (pointer?.includes("configuration"))
      append("configuration", detail);
    else if (pointer?.includes("provider_ids")) append("provider_ids", detail);
    else append("general", detail);
  }
  return errors;
};

export const createScanConfiguration = async (
  _prevState: ScanConfigurationActionState,
  formData: FormData,
): Promise<ScanConfigurationActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = {
    name: formData.get("name"),
    configuration: formData.get("configuration"),
    provider_ids: collectProviderIds(formData),
  };

  const validated = scanConfigurationFormSchema.safeParse(formDataObject);
  if (!validated.success) {
    const fieldErrors = validated.error.flatten().fieldErrors;
    return {
      errors: {
        name: fieldErrors?.name?.[0],
        configuration: fieldErrors?.configuration?.[0],
        provider_ids: fieldErrors?.provider_ids?.[0],
      },
    };
  }

  const { name, configuration, provider_ids } = validated.data;

  let parsedConfig: Record<string, unknown>;
  try {
    parsedConfig = parseConfiguration(configuration);
  } catch (e) {
    return {
      errors: {
        configuration:
          e instanceof Error ? e.message : "Failed to parse configuration",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/scan-configurations`);
    const bodyData: ScanConfigurationRequestBody = {
      data: {
        type: "scan-configurations",
        attributes: {
          name,
          configuration: parsedConfig,
          provider_ids,
        },
      },
    };
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: mapApiErrorsToFields(
          errorData,
          `Failed to create Scan Configuration: ${response.statusText}`,
        ),
      };
    }

    const data = await response.json();
    revalidatePath(SCAN_CONFIGURATION_PATH);
    return {
      success: "Scan Configuration created successfully!",
      data: data.data as ScanConfigurationData,
    };
  } catch (error) {
    console.error("Error creating Scan Configuration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating Scan Configuration. Please try again.",
      },
    };
  }
};

export const updateScanConfiguration = async (
  _prevState: ScanConfigurationActionState,
  formData: FormData,
): Promise<ScanConfigurationActionState> => {
  const id = formData.get("id");
  if (!id) {
    return {
      errors: { general: "Scan Configuration ID is required for update" },
    };
  }
  const idResult = scanConfigurationIdSchema.safeParse(String(id));
  if (!idResult.success) {
    return { errors: { general: "Invalid Scan Configuration ID" } };
  }
  const validId = idResult.data;
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = {
    name: formData.get("name"),
    configuration: formData.get("configuration"),
    provider_ids: collectProviderIds(formData),
  };

  const validated = scanConfigurationFormSchema.safeParse(formDataObject);
  if (!validated.success) {
    const fieldErrors = validated.error.flatten().fieldErrors;
    return {
      errors: {
        name: fieldErrors?.name?.[0],
        configuration: fieldErrors?.configuration?.[0],
        provider_ids: fieldErrors?.provider_ids?.[0],
      },
    };
  }

  const { name, configuration, provider_ids } = validated.data;

  let parsedConfig: Record<string, unknown>;
  try {
    parsedConfig = parseConfiguration(configuration);
  } catch (e) {
    return {
      errors: {
        configuration:
          e instanceof Error ? e.message : "Failed to parse configuration",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/scan-configurations/${validId}`);
    const bodyData: ScanConfigurationRequestBody = {
      data: {
        type: "scan-configurations",
        id: validId,
        attributes: {
          name,
          configuration: parsedConfig,
          provider_ids,
        },
      },
    };
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: mapApiErrorsToFields(
          errorData,
          `Failed to update Scan Configuration: ${response.statusText}`,
        ),
      };
    }

    const data = await response.json();
    revalidatePath(SCAN_CONFIGURATION_PATH);
    return {
      success: "Scan Configuration updated successfully!",
      data: data.data as ScanConfigurationData,
    };
  } catch (error) {
    console.error("Error updating Scan Configuration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating Scan Configuration. Please try again.",
      },
    };
  }
};

// Attach/detach providers on a scan configuration without touching its name or
// YAML — a partial PATCH of `provider_ids` only. Used by the provider row to
// associate/disassociate a config (editing the config itself lives in the Scan
// Config view). The backend's `(tenant, provider)` uniqueness means attaching a
// provider here moves it off any other config automatically.
export const setScanConfigurationProviders = async (
  configId: string,
  providerIds: string[],
): Promise<ScanConfigurationActionState> => {
  const idResult = scanConfigurationIdSchema.safeParse(configId);
  if (!idResult.success) {
    return { errors: { general: "Invalid Scan Configuration ID" } };
  }
  const validId = idResult.data;
  const providerIdsResult = providerIdsSchema.safeParse(providerIds);
  if (!providerIdsResult.success) {
    return { errors: { provider_ids: "Invalid provider ID" } };
  }
  const validProviderIds = providerIdsResult.data;
  const headers = await getAuthHeaders({ contentType: true });

  try {
    const url = new URL(`${apiBaseUrl}/scan-configurations/${validId}`);
    // Partial update: only provider_ids (name/configuration are optional on the
    // backend update serializer), so we don't type this as the full request body.
    const bodyData = {
      data: {
        type: "scan-configurations" as const,
        id: validId,
        attributes: { provider_ids: validProviderIds },
      },
    };
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: mapApiErrorsToFields(
          errorData,
          `Failed to update Scan Configuration: ${response.statusText}`,
        ),
      };
    }

    revalidatePath(SCAN_CONFIGURATION_PATH);
    revalidatePath("/providers");
    return { success: "Scan Configuration updated successfully!" };
  } catch (error) {
    console.error("Error updating Scan Configuration providers:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating Scan Configuration. Please try again.",
      },
    };
  }
};

export const listScanConfigurations = async (): Promise<
  ScanConfigurationData[]
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configurations`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) {
      throw new Error(
        `Failed to list Scan Configurations: ${response.statusText}`,
      );
    }
    const json = await response.json();
    return (json.data || []) as ScanConfigurationData[];
  } catch (error) {
    // Re-throw so callers can distinguish a fetch/auth failure from an empty
    // result. Collapsing errors into `[]` would render a false "no scan
    // configurations" state and overwrite the table on a failed refresh.
    console.error("Error listing Scan Configurations:", error);
    throw error;
  }
};

export const getScanConfiguration = async (
  id: string,
): Promise<ScanConfigurationData | undefined> => {
  const idResult = scanConfigurationIdSchema.safeParse(id);
  if (!idResult.success) return undefined;
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configurations/${idResult.data}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) return undefined;
    const json = await response.json();
    return json.data as ScanConfigurationData;
  } catch (error) {
    console.error("Error fetching Scan Configuration:", error);
    return undefined;
  }
};

export const deleteScanConfiguration = async (
  _prevState: DeleteScanConfigurationActionState,
  formData: FormData,
): Promise<DeleteScanConfigurationActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const id = formData.get("id");
  if (!id) {
    return {
      errors: { general: "Scan Configuration ID is required for deletion" },
    };
  }
  const idResult = scanConfigurationIdSchema.safeParse(String(id));
  if (!idResult.success) {
    return { errors: { general: "Invalid Scan Configuration ID" } };
  }
  try {
    const url = new URL(`${apiBaseUrl}/scan-configurations/${idResult.data}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete Scan Configuration: ${response.statusText}`,
      );
    }
    revalidatePath(SCAN_CONFIGURATION_PATH);
    return { success: "Scan Configuration deleted successfully!" };
  } catch (error) {
    console.error("Error deleting Scan Configuration:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting Scan Configuration. Please try again.",
      },
    };
  }
};
