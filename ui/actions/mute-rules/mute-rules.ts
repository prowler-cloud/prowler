"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";

import {
  DeleteMuteRuleActionState,
  MuteRuleActionState,
  MuteRuleData,
  MuteRulesResponse,
} from "./types";

interface GetMuteRulesParams {
  page?: number;
  pageSize?: number;
  sort?: string;
  filters?: Record<string, string>;
}

export const getMuteRules = async (
  params: GetMuteRulesParams = {},
): Promise<MuteRulesResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/mute-rules`);

  if (params.page) {
    url.searchParams.append("page[number]", params.page.toString());
  }
  if (params.pageSize) {
    url.searchParams.append("page[size]", params.pageSize.toString());
  }
  if (params.sort) {
    url.searchParams.append("sort", params.sort);
  }
  if (params.filters) {
    Object.entries(params.filters).forEach(([key, value]) => {
      url.searchParams.append(`filter[${key}]`, value);
    });
  }

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
      next: { revalidate: 0 },
    });

    if (!response.ok) {
      // Don't log authorization errors as they're expected when endpoint is not available
      if (response.status !== 401 && response.status !== 403) {
        console.error(`Failed to fetch mute rules: ${response.statusText}`);
      }
      return undefined;
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching mute rules:", error);
    return undefined;
  }
};

export const getMuteRule = async (
  id: string,
): Promise<MuteRuleData | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/mute-rules/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      // Don't log authorization errors as they're expected when endpoint is not available
      if (response.status !== 401 && response.status !== 403) {
        console.error(`Failed to fetch mute rule: ${response.statusText}`);
      }
      return undefined;
    }

    const data = await response.json();
    return data.data;
  } catch (error) {
    console.error("Error fetching mute rule:", error);
    return undefined;
  }
};

export const createMuteRule = async (
  _prevState: MuteRuleActionState,
  formData: FormData,
): Promise<MuteRuleActionState> => {
  const headers = await getAuthHeaders({ contentType: true });

  const name = formData.get("name") as string;
  const reason = formData.get("reason") as string;
  const findingIdsRaw = formData.get("finding_ids") as string;

  // Validate required fields
  if (!name || name.length < 3) {
    return {
      errors: {
        name: "Name must be at least 3 characters",
      },
    };
  }

  if (!reason || reason.length < 3) {
    return {
      errors: {
        reason: "Reason must be at least 3 characters",
      },
    };
  }

  let findingIds: string[];
  try {
    findingIds = JSON.parse(findingIdsRaw);
    if (!Array.isArray(findingIds) || findingIds.length === 0) {
      throw new Error("Invalid finding IDs");
    }
  } catch {
    return {
      errors: {
        finding_ids: "At least one finding must be selected",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/mute-rules`);

    const bodyData = {
      data: {
        type: "mute-rules",
        attributes: {
          name,
          reason,
          finding_ids: findingIds,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      let errorMessage = `Failed to create mute rule: ${response.statusText}`;
      try {
        const errorData = await response.json();
        errorMessage =
          errorData?.errors?.[0]?.detail || errorData?.message || errorMessage;
      } catch {
        // JSON parsing failed, use default error message
      }
      throw new Error(errorMessage);
    }

    revalidatePath("/findings");
    revalidatePath("/mutelist");

    return {
      success: "Mute rule created successfully! Findings are now muted.",
    };
  } catch (error) {
    console.error("Error creating mute rule:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error creating mute rule. Please try again.",
      },
    };
  }
};

export const updateMuteRule = async (
  _prevState: MuteRuleActionState,
  formData: FormData,
): Promise<MuteRuleActionState> => {
  const headers = await getAuthHeaders({ contentType: true });

  const id = formData.get("id") as string;
  const name = formData.get("name") as string;
  const reason = formData.get("reason") as string;
  const enabledRaw = formData.get("enabled") as string;

  if (!id) {
    return {
      errors: {
        general: "Mute rule ID is required for update",
      },
    };
  }

  // Validate optional fields if provided
  const validateOptionalField = (
    value: string | null,
    fieldName: string,
    minLength = 3,
  ): MuteRuleActionState | null => {
    if (value && value.length > 0 && value.length < minLength) {
      return {
        errors: {
          [fieldName]: `${fieldName.charAt(0).toUpperCase() + fieldName.slice(1)} must be at least ${minLength} characters`,
        },
      };
    }
    return null;
  };

  const nameError = validateOptionalField(name, "name");
  if (nameError) return nameError;

  const reasonError = validateOptionalField(reason, "reason");
  if (reasonError) return reasonError;

  try {
    const url = new URL(`${apiBaseUrl}/mute-rules/${id}`);

    const attributes: Record<string, string | boolean> = {};
    if (name) attributes.name = name;
    if (reason) attributes.reason = reason;
    if (enabledRaw !== null && enabledRaw !== undefined) {
      attributes.enabled = enabledRaw === "true";
    }

    const bodyData = {
      data: {
        type: "mute-rules",
        id,
        attributes,
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      let errorMessage = `Failed to update mute rule: ${response.statusText}`;
      try {
        const errorData = await response.json();
        errorMessage =
          errorData?.errors?.[0]?.detail || errorData?.message || errorMessage;
      } catch {
        // JSON parsing failed, use default error message
      }
      throw new Error(errorMessage);
    }

    revalidatePath("/mutelist");

    return { success: "Mute rule updated successfully!" };
  } catch (error) {
    console.error("Error updating mute rule:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error updating mute rule. Please try again.",
      },
    };
  }
};

export const toggleMuteRule = async (
  id: string,
  enabled: boolean,
): Promise<{ success?: string; error?: string }> => {
  const headers = await getAuthHeaders({ contentType: true });

  try {
    const url = new URL(`${apiBaseUrl}/mute-rules/${id}`);

    const bodyData = {
      data: {
        type: "mute-rules",
        id,
        attributes: {
          enabled,
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(bodyData),
    });

    if (!response.ok) {
      let errorMessage = `Failed to toggle mute rule: ${response.statusText}`;
      try {
        const errorData = await response.json();
        errorMessage =
          errorData?.errors?.[0]?.detail || errorData?.message || errorMessage;
      } catch {
        // JSON parsing failed, use default error message
      }
      throw new Error(errorMessage);
    }

    revalidatePath("/mutelist");

    return {
      success: `Mute rule ${enabled ? "enabled" : "disabled"} successfully!`,
    };
  } catch (error) {
    console.error("Error toggling mute rule:", error);
    return {
      error:
        error instanceof Error
          ? error.message
          : "Error toggling mute rule. Please try again.",
    };
  }
};

export const deleteMuteRule = async (
  _prevState: DeleteMuteRuleActionState,
  formData: FormData,
): Promise<DeleteMuteRuleActionState> => {
  const headers = await getAuthHeaders({ contentType: true });
  const id = formData.get("id") as string;

  if (!id) {
    return {
      errors: {
        general: "Mute rule ID is required for deletion",
      },
    };
  }

  try {
    const url = new URL(`${apiBaseUrl}/mute-rules/${id}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.errors?.[0]?.detail ||
          `Failed to delete mute rule: ${response.statusText}`,
      );
    }

    revalidatePath("/mutelist");

    return { success: "Mute rule deleted successfully!" };
  } catch (error) {
    console.error("Error deleting mute rule:", error);
    return {
      errors: {
        general:
          error instanceof Error
            ? error.message
            : "Error deleting mute rule. Please try again.",
      },
    };
  }
};

// Note: Adding findings to existing mute rules is not supported by the API.
// The MuteRuleUpdateSerializer only allows updating name, reason, and enabled fields.
// finding_ids can only be specified when creating a new mute rule.

// Note: Unmute functionality is not currently supported by the API.
// The FindingViewSet only allows GET operations, and deleting a mute rule
// does not unmute the findings ("Previously muted findings remain muted").
