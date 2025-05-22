"use server";

import { revalidatePath } from "next/cache";

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

export async function updateTenantName(formData: FormData) {
  const headers = await getAuthHeaders({ contentType: true });
  const tenantId = formData.get("tenantId") as string;
  const name = formData.get("name") as string;

  if (!tenantId || !name) {
    return {
      errors: [{ detail: "Tenant ID and name are required" }],
    };
  }

  const payload = {
    data: {
      type: "tenants",
      id: tenantId,
      attributes: {
        name,
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

    const data = await response.json();
    revalidatePath("/profile");
    return data;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error updating tenant name:", error);
    return {
      errors: [{ detail: `Error updating tenant name: ${error}` }],
    };
  }
}
