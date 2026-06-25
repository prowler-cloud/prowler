"use server";

import yaml from "js-yaml";
import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { scanConfigFormSchema } from "@/types/formSchemas";
import {
  DeleteScanConfigActionState,
  ScanConfigActionState,
  ScanConfigData,
  ScanConfigErrors,
  ScanConfigRequestBody,
} from "@/types/scan-configs";

const SCAN_CONFIG_PATH = "/scan-config";

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

export const createScanConfig = async (
  _prevState: ScanConfigActionState,
  formData: FormData,
): Promise<ScanConfigActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = {
    name: formData.get("name"),
    configuration: formData.get("configuration"),
    provider_ids: collectProviderIds(formData),
  };

  const validated = scanConfigFormSchema.safeParse(formDataObject);
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
    const url = new URL(`${apiBaseUrl}/scan-configs`);
    const bodyData: ScanConfigRequestBody = {
      data: {
        type: "scan-configs",
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
        `Failed to create Scan Config: ${response.statusText}`;
      const pointer = errorData?.errors?.[0]?.source?.pointer as
        | string
        | undefined;
      const errors: ScanConfigErrors = {};
      if (pointer?.includes("name")) errors.name = detail;
      else if (pointer?.includes("configuration"))
        errors.configuration = detail;
      else if (pointer?.includes("provider_ids")) errors.provider_ids = detail;
      else errors.general = detail;
      return { errors };
    }

    const data = await response.json();
    revalidatePath(SCAN_CONFIG_PATH);
    return {
      success: "Scan Config created successfully!",
      data: data.data as ScanConfigData,
    };
  } catch (error) {
    console.error("Error creating Scan Config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating Scan Config. Please try again.",
      },
    };
  }
};

export const updateScanConfig = async (
  _prevState: ScanConfigActionState,
  formData: FormData,
): Promise<ScanConfigActionState> => {
  const id = formData.get("id");
  if (!id) {
    return { errors: { general: "Scan Config ID is required for update" } };
  }
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = {
    name: formData.get("name"),
    configuration: formData.get("configuration"),
    provider_ids: collectProviderIds(formData),
  };

  const validated = scanConfigFormSchema.safeParse(formDataObject);
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
    const url = new URL(`${apiBaseUrl}/scan-configs/${id}`);
    const bodyData: ScanConfigRequestBody = {
      data: {
        type: "scan-configs",
        id: String(id),
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
        `Failed to update Scan Config: ${response.statusText}`;
      return { errors: { general: detail } };
    }

    const data = await response.json();
    revalidatePath(SCAN_CONFIG_PATH);
    return {
      success: "Scan Config updated successfully!",
      data: data.data as ScanConfigData,
    };
  } catch (error) {
    console.error("Error updating Scan Config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating Scan Config. Please try again.",
      },
    };
  }
};

export const getScanConfigSchema = async (): Promise<Record<
  string,
  unknown
> | null> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configs/schema`);
  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) {
      throw new Error(
        `Failed to fetch Scan Config schema: ${response.statusText}`,
      );
    }
    const json = await response.json();
    const schema = json?.data?.attributes?.schema as
      | Record<string, unknown>
      | undefined;
    return schema ?? null;
  } catch (error) {
    console.error("Error fetching Scan Config schema:", error);
    return null;
  }
};

export const listScanConfigs = async (): Promise<ScanConfigData[]> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configs`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) {
      throw new Error(`Failed to list Scan Configs: ${response.statusText}`);
    }
    const json = await response.json();
    return (json.data || []) as ScanConfigData[];
  } catch (error) {
    console.error("Error listing Scan Configs:", error);
    return [];
  }
};

export const getScanConfig = async (
  id: string,
): Promise<ScanConfigData | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scan-configs/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });
    if (!response.ok) return undefined;
    const json = await response.json();
    return json.data as ScanConfigData;
  } catch (error) {
    console.error("Error fetching Scan Config:", error);
    return undefined;
  }
};

export const deleteScanConfig = async (
  _prevState: DeleteScanConfigActionState,
  formData: FormData,
): Promise<DeleteScanConfigActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const id = formData.get("id");
  if (!id) {
    return { errors: { general: "Scan Config ID is required for deletion" } };
  }
  try {
    const url = new URL(`${apiBaseUrl}/scan-configs/${id}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete Scan Config: ${response.statusText}`,
      );
    }
    revalidatePath(SCAN_CONFIG_PATH);
    return { success: "Scan Config deleted successfully!" };
  } catch (error) {
    console.error("Error deleting Scan Config:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting Scan Config. Please try again.",
      },
    };
  }
};
