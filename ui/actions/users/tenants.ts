"use server";

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
