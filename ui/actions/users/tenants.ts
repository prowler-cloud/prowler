"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

export const getAllTenants = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/tenants`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch tenants data: ${response.statusText}`);
    }

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching tenants:", error);
    return undefined;
  }
};

const editTenantFormSchema = z
  .object({
    tenantId: z.string(),
    name: z.string().trim().min(1, { message: "Name is required" }),
    currentName: z.string(),
  })
  .refine((data) => data.name !== data.currentName, {
    message: "Name must be different from the current name",
    path: ["name"],
  });

export async function updateTenantName(_prevState: any, formData: FormData) {
  const headers = await getAuthHeaders({ contentType: true });
  const formDataObject = Object.fromEntries(formData);
  const validatedData = editTenantFormSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const formFieldErrors = validatedData.error.flatten().fieldErrors;

    return {
      errors: {
        name: formFieldErrors?.name?.[0],
      },
    };
  }

  const { tenantId, name } = validatedData.data;

  const payload = {
    data: {
      type: "tenants",
      id: tenantId,
      attributes: {
        name: name.trim(),
      },
    },
  };

  try {
    const url = new URL(`${apiBaseUrl}/tenants/${tenantId}`);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Failed to update tenant name: ${response.statusText}`);
    }

    await handleApiResponse(response, "/profile", false);
    return { success: "Tenant name updated successfully!" };
  } catch (error) {
    return handleApiError(error);
  }
}

const switchTenantSchema = z.object({
  tenantId: z.uuid(),
});

interface SwitchTenantSuccess {
  success: true;
  accessToken: string;
  refreshToken: string;
}

interface SwitchTenantError {
  error: string;
}

export type SwitchTenantState = SwitchTenantSuccess | SwitchTenantError;

export async function switchTenant(
  _prevState: SwitchTenantState | null,
  formData: FormData,
): Promise<SwitchTenantState> {
  const formDataObject = Object.fromEntries(formData);
  const validatedData = switchTenantSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    return { error: "Invalid tenant ID" };
  }

  const { tenantId } = validatedData.data;
  const headers = await getAuthHeaders({ contentType: true });

  const payload = {
    data: {
      type: "tokens-switch-tenant",
      attributes: {
        tenant_id: tenantId,
      },
    },
  };

  try {
    const url = new URL(`${apiBaseUrl}/tokens/switch`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      const errorDetail =
        errorData?.errors?.[0]?.detail ||
        `Failed to switch tenant: ${response.statusText}`;
      throw new Error(errorDetail);
    }

    const data = await response.json();
    const accessToken = data?.data?.attributes?.access;
    const refreshToken = data?.data?.attributes?.refresh;

    if (!accessToken || !refreshToken) {
      throw new Error("Missing tokens in switch tenant response");
    }

    return { success: true, accessToken, refreshToken };
  } catch (error) {
    return handleApiError(error);
  }
}

const createTenantSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, { message: "Name is required" })
    .max(100, { message: "Name must be 100 characters or less" }),
});

export interface CreateTenantState {
  success?: boolean;
  tenantId?: string;
  error?: string;
}

export async function createTenant(
  _prevState: CreateTenantState | null,
  formData: FormData,
): Promise<CreateTenantState> {
  const formDataObject = Object.fromEntries(formData);
  const validatedData = createTenantSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    const fieldErrors = validatedData.error.flatten().fieldErrors;
    return { error: fieldErrors?.name?.[0] || "Invalid input" };
  }

  const { name } = validatedData.data;
  const headers = await getAuthHeaders({ contentType: true });

  const payload = {
    data: {
      type: "tenants",
      attributes: { name },
    },
  };

  try {
    const url = new URL(`${apiBaseUrl}/tenants`);
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      const errorDetail =
        errorData?.errors?.[0]?.detail ||
        `Failed to create tenant: ${response.statusText}`;
      throw new Error(errorDetail);
    }

    const data = await response.json();
    const tenantId = data?.data?.id;

    if (!tenantId) {
      throw new Error("Missing tenant ID in create response");
    }

    revalidatePath("/profile");
    return { success: true, tenantId };
  } catch (error) {
    return handleApiError(error);
  }
}

const deleteTenantSchema = z.object({
  tenantId: z.uuid(),
});

const switchThenDeleteTenantSchema = z.object({
  tenantId: z.uuid(),
  targetTenantId: z.uuid(),
});

export interface DeleteTenantState {
  success?: boolean;
  error?: string;
}

export async function deleteTenant(
  _prevState: DeleteTenantState | null,
  formData: FormData,
): Promise<DeleteTenantState> {
  const formDataObject = Object.fromEntries(formData);
  const validatedData = deleteTenantSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    return { error: "Invalid tenant ID" };
  }

  const { tenantId } = validatedData.data;
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/tenants/${tenantId}`);
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      const errorDetail =
        errorData?.errors?.[0]?.detail ||
        `Failed to delete tenant: ${response.statusText}`;
      throw new Error(errorDetail);
    }

    revalidatePath("/profile");
    return { success: true };
  } catch (error) {
    return handleApiError(error);
  }
}

export interface SwitchThenDeleteTenantState {
  success?: boolean;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
}

export async function switchThenDeleteTenant(
  _prevState: SwitchThenDeleteTenantState | null,
  formData: FormData,
): Promise<SwitchThenDeleteTenantState> {
  const formDataObject = Object.fromEntries(formData);
  const validatedData = switchThenDeleteTenantSchema.safeParse(formDataObject);

  if (!validatedData.success) {
    return { error: "Invalid tenant or target tenant ID" };
  }

  const { tenantId, targetTenantId } = validatedData.data;
  const headers = await getAuthHeaders({ contentType: true });

  // Step 1: Switch to the target tenant (current token is still valid)
  const switchPayload = {
    data: {
      type: "tokens-switch-tenant",
      attributes: {
        tenant_id: targetTenantId,
      },
    },
  };

  let newAccessToken: string;
  let newRefreshToken: string;

  try {
    const switchUrl = new URL(`${apiBaseUrl}/tokens/switch`);
    const switchResponse = await fetch(switchUrl.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(switchPayload),
    });

    if (!switchResponse.ok) {
      const errorData = await switchResponse.json().catch(() => null);
      const errorDetail =
        errorData?.errors?.[0]?.detail ||
        `Failed to switch tenant: ${switchResponse.statusText}`;
      throw new Error(errorDetail);
    }

    const switchData = await switchResponse.json();
    newAccessToken = switchData?.data?.attributes?.access;
    newRefreshToken = switchData?.data?.attributes?.refresh;

    if (!newAccessToken || !newRefreshToken) {
      throw new Error("Missing tokens in switch tenant response");
    }
  } catch (error) {
    return handleApiError(error);
  }

  // Step 2: Delete the old tenant using the NEW token
  const deleteHeaders: Record<string, string> = {
    Accept: "application/vnd.api+json",
    Authorization: `Bearer ${newAccessToken}`,
  };

  try {
    const deleteUrl = new URL(`${apiBaseUrl}/tenants/${tenantId}`);
    const deleteResponse = await fetch(deleteUrl.toString(), {
      method: "DELETE",
      headers: deleteHeaders,
    });

    if (!deleteResponse.ok) {
      const errorData = await deleteResponse.json().catch(() => null);
      const errorDetail =
        errorData?.errors?.[0]?.detail ||
        `Failed to delete tenant: ${deleteResponse.statusText}`;
      // Switch succeeded but delete failed — return tokens so client can still update session
      return {
        error: errorDetail,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    }

    revalidatePath("/profile");
    return {
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    // Switch succeeded but delete threw — return tokens so client can still update session
    const errorResult = handleApiError(error);
    return {
      ...errorResult,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }
}
