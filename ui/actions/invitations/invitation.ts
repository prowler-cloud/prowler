"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  parseStringify,
} from "@/lib";

export const getInvitations = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/invitations");

  const url = new URL(`${apiBaseUrl}/tenants/invitations`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const invitations = await fetch(url.toString(), {
      headers,
    });
    const data = await invitations.json();
    const parsedData = parseStringify(data);
    revalidatePath("/invitations");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching invitations:", error);
    return undefined;
  }
};

export const sendInvite = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const email = formData.get("email");
  const role = formData.get("role");
  const url = new URL(`${apiBaseUrl}/tenants/invitations`);

  const body = JSON.stringify({
    data: {
      type: "invitations",
      attributes: {
        email,
      },
      relationships: {
        roles: {
          data: role
            ? [
                {
                  id: role,
                  type: "roles",
                },
              ]
            : [],
        },
      },
    },
  });

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body,
    });
    const data = await response.json();

    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateInvite = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const invitationId = formData.get("invitationId");
  const invitationEmail = formData.get("invitationEmail");
  const roleId = formData.get("role");
  const expiresAt =
    formData.get("expires_at") ||
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const url = new URL(`${apiBaseUrl}/tenants/invitations/${invitationId}`);

  const body: any = {
    data: {
      type: "invitations",
      id: invitationId,
      attributes: {},
      relationships: {},
    },
  };

  // Only add attributes that exist in the formData
  if (invitationEmail) {
    body.data.attributes.email = invitationEmail;
  }
  if (expiresAt) {
    body.data.attributes.expires_at = expiresAt;
  }
  if (roleId) {
    body.data.relationships.roles = {
      data: [
        {
          id: roleId,
          type: "roles",
        },
      ],
    };
  }

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.json();
      return { error };
    }

    const data = await response.json();
    revalidatePath("/invitations");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getInvitationInfoById = async (invitationId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/tenants/invitations/${invitationId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    const data = await response.json();
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const revokeInvite = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const invitationId = formData.get("invitationId");

  if (!invitationId) {
    return { error: "Invitation ID is required" };
  }

  const url = new URL(`${apiBaseUrl}/tenants/invitations/${invitationId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.message || "Failed to revoke the invitation",
        );
      } catch {
        throw new Error("Failed to revoke the invitation");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/invitations");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error revoking invitation:", error);
    return { error: getErrorMessage(error) };
  }
};
