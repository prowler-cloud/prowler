"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib/helper";

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

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/profile");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
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

export async function updateTenantName(prevState: any, formData: FormData) {
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

    await response.json();
    revalidatePath("/profile");
    return { success: "Tenant name updated successfully!" };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error updating tenant name:", error);
    return {
      errors: {
        general: "Error updating tenant name. Please try again.",
      },
    };
  }
}
