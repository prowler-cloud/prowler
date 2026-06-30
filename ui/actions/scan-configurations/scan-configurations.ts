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

const SCAN_CONFIGURATION_PATH = "/scan-configurations";

// Scan Configuration IDs are UUIDs. Validate before interpolating into request
// URLs so a malformed/crafted value can't inject path segments (SSRF / path
// injection).
const scanConfigurationIdSchema = z.uuid();

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
      const detail =
        errorData?.errors?.[0]?.detail ||
        errorData?.message ||
        `Failed to create Scan Configuration: ${response.statusText}`;
      const pointer = errorData?.errors?.[0]?.source?.pointer as
        | string
        | undefined;
      const errors: ScanConfigurationErrors = {};
      if (pointer?.includes("name")) errors.name = detail;
      else if (pointer?.includes("configuration"))
        errors.configuration = detail;
      else if (pointer?.includes("provider_ids")) errors.provider_ids = detail;
      else errors.general = detail;
      return { errors };
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
      const detail =
        errorData?.errors?.[0]?.detail ||
        errorData?.message ||
        `Failed to update Scan Configuration: ${response.statusText}`;
      return { errors: { general: detail } };
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

export const getScanConfigurationSchema = async (): Promise<Record<
  string,
  unknown
> | null> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configurations/schema`);
  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) {
      throw new Error(
        `Failed to fetch Scan Configuration schema: ${response.statusText}`,
      );
    }
    const json = await response.json();
    const schema = json?.data?.attributes?.schema as
      | Record<string, unknown>
      | undefined;
    return schema ?? null;
  } catch (error) {
    console.error("Error fetching Scan Configuration schema:", error);
    return null;
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
