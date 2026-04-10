"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";

import { auth } from "@/auth.config";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  TENANT_MEMBERSHIP_ROLE,
  type TenantMembershipRole,
} from "@/types/users";

interface UserAttributes {
  name?: string;
  email?: string;
  company_name?: string;
  password?: string;
}

interface MembershipResource {
  id: string;
}

const getUsersSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  query: z.string().default(""),
  sort: z.string().optional().default(""),
  filters: z
    .record(
      z.string(),
      z.union([z.string(), z.array(z.string()), z.number()]).optional(),
    )
    .default({}),
  pageSize: z.coerce.number().int().min(1).default(10),
});

const updateUserSchema = z.object({
  userId: z.uuid(),
  name: z.string().min(1).optional(),
  email: z.email().optional(),
  company_name: z.string().optional(),
  password: z.string().min(1).optional(),
});

const deleteUserSchema = z.object({
  userId: z.uuid(),
});

const removeUserFromTenantSchema = z.object({
  userId: z.uuid(),
  tenantId: z.uuid(),
});

const updateUserRoleSchema = z.object({
  userId: z.uuid(),
  roleId: z.uuid(),
});

export const getUsers = async (
  rawParams: {
    page?: number | string;
    query?: string;
    sort?: string;
    filters?: Record<string, string | string[] | number | undefined>;
    pageSize?: number | string;
  } = {},
) => {
  const parsed = getUsersSchema.safeParse(rawParams);
  if (!parsed.success) {
    console.error("Invalid getUsers params:", parsed.error.flatten());
    return undefined;
  }
  const { page, query, sort, filters, pageSize } = parsed.data;

  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/users?include=roles");

  const url = new URL(`${apiBaseUrl}/users?include=roles`);

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
    const users = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    return undefined;
  }
};

export const updateUser = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const rawData = {
    userId: formData.get("userId"),
    name: formData.get("name") ?? undefined,
    email: formData.get("email") ?? undefined,
    company_name: formData.get("company_name") ?? undefined,
    password: formData.get("password") ?? undefined,
  };
  const parsed = updateUserSchema.safeParse(rawData);
  if (!parsed.success) {
    return { error: "Invalid user data" };
  }
  const { userId, name, email, company_name, password } = parsed.data;

  const url = new URL(`${apiBaseUrl}/users/${userId}`);

  // Prepare attributes to send based on changes
  const attributes: UserAttributes = {};

  // Add only changed fields
  if (name !== undefined) attributes.name = name;
  if (email !== undefined) attributes.email = email;
  if (company_name !== undefined) attributes.company_name = company_name;
  if (password !== undefined) attributes.password = password;

  // If no fields have changed, don't send the request
  if (Object.keys(attributes).length === 0) {
    return { error: "No changes detected" };
  }

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "users",
          id: userId,
          attributes: attributes,
        },
      }),
    });

    return handleApiResponse(response, "/users");
  } catch (error) {
    handleApiError(error);
  }
};

export const updateUserRole = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const parsed = updateUserRoleSchema.safeParse({
    userId: formData.get("userId"),
    roleId: formData.get("roleId"),
  });
  if (!parsed.success) {
    return { error: "userId and roleId are required" };
  }
  const { userId, roleId } = parsed.data;

  const url = new URL(`${apiBaseUrl}/users/${userId}/relationships/roles`);

  const requestBody = {
    data: [
      {
        type: "roles",
        id: roleId,
      },
    ],
  };

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(requestBody),
    });

    return handleApiResponse(response, "/users");
  } catch (error) {
    handleApiError(error);
  }
};

export const deleteUser = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const parsed = deleteUserSchema.safeParse({ userId: formData.get("userId") });
  if (!parsed.success) {
    return { error: "User ID is required" };
  }
  const { userId } = parsed.data;

  const url = new URL(`${apiBaseUrl}/users/${userId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      // Parse error response
      const errorData = await response.json();
      return {
        errors: errorData.errors || [{ detail: "Failed to delete the user" }],
      };
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/users");
    return data || { success: true };
  } catch (error) {
    handleApiError(error);
  }
};

interface ServerActionErrorDetail {
  detail: string;
  code?: string;
}

interface ServerActionErrorResponse {
  errors: ServerActionErrorDetail[];
}

interface RemoveUserFromTenantSuccess {
  success: true;
}

type RemoveUserFromTenantResult =
  | RemoveUserFromTenantSuccess
  | ServerActionErrorResponse;

const toErrorResponse = (detail: string): ServerActionErrorResponse => ({
  errors: [{ detail }],
});

export const removeUserFromTenant = async (
  formData: FormData,
): Promise<RemoveUserFromTenantResult> => {
  const headers = await getAuthHeaders({ contentType: false });
  const parsed = removeUserFromTenantSchema.safeParse({
    userId: formData.get("userId"),
    tenantId: formData.get("tenantId"),
  });
  if (!parsed.success) {
    return toErrorResponse("userId and tenantId are required");
  }
  const { userId, tenantId } = parsed.data;

  // Resolve the target user's membership id for the current tenant on the
  // server so the client form can open instantly without a prefetch.
  //
  // We cannot use `/users/{userId}/memberships` here: that endpoint ignores
  // the path user id and always returns the authenticated user's memberships,
  // which would make us try to delete the caller's own membership.
  const listUrl = new URL(`${apiBaseUrl}/tenants/${tenantId}/memberships`);
  listUrl.searchParams.append("filter[user]", userId);
  listUrl.searchParams.append("page[size]", "1");

  let targetMembershipId: string | null = null;
  try {
    const listResponse = await fetch(listUrl.toString(), { headers });
    if (!listResponse.ok) {
      const errorData = await listResponse.json().catch(() => ({}));
      return {
        errors: errorData.errors ?? [
          { detail: "Failed to resolve the user's membership" },
        ],
      };
    }
    const listData = (await listResponse.json()) as {
      data?: MembershipResource[];
    };
    targetMembershipId = listData?.data?.[0]?.id ?? null;
  } catch (error) {
    const handled = handleApiError(error);
    return toErrorResponse(
      handled?.error ?? "Failed to resolve the user's membership",
    );
  }

  if (!targetMembershipId) {
    return toErrorResponse(
      "This user is not a member of the current organization.",
    );
  }

  const url = new URL(
    `${apiBaseUrl}/tenants/${tenantId}/memberships/${targetMembershipId}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        errors: errorData.errors ?? [
          { detail: "Failed to expel the user from the organization" },
        ],
      };
    }

    revalidatePath("/users");
    return { success: true };
  } catch (error) {
    const handled = handleApiError(error);
    return toErrorResponse(
      handled?.error ?? "Failed to expel the user from the organization",
    );
  }
};

interface MembershipAttributesResource {
  id: string;
  attributes?: {
    role?: string;
  };
}

/**
 * Resolve the active user's role inside the current tenant by querying the
 * tenant memberships list with `filter[user]`. Returns `null` if the role
 * cannot be determined (missing session, API error, or no match), so the
 * caller can default-deny the destructive UI action.
 */
export const getCurrentUserTenantRole =
  async (): Promise<TenantMembershipRole | null> => {
    const session = await auth();
    const userId = session?.userId;
    const tenantId = session?.tenantId;
    if (!userId || !tenantId) {
      return null;
    }

    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(`${apiBaseUrl}/tenants/${tenantId}/memberships`);
    url.searchParams.append("filter[user]", userId);
    url.searchParams.append("page[size]", "1");

    try {
      const response = await fetch(url.toString(), { headers });
      if (!response.ok) {
        return null;
      }
      const body = (await response.json()) as {
        data?: MembershipAttributesResource[];
      };
      const role = body?.data?.[0]?.attributes?.role;
      if (
        role === TENANT_MEMBERSHIP_ROLE.Owner ||
        role === TENANT_MEMBERSHIP_ROLE.Member
      ) {
        return role;
      }
      return null;
    } catch (error) {
      console.error("Error resolving current user's tenant role:", error);
      return null;
    }
  };

export const getUserInfo = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/users/me?include=roles,memberships,memberships.tenant`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user data: ${response.statusText}`);
    }

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching profile:", error);
    return undefined;
  }
};

export const getUserMemberships = async (userId: string) => {
  if (!userId) {
    return { data: [] };
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/users/${userId}/memberships`);
  url.searchParams.append("page[size]", "100");

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching user memberships:", error);
    return { data: [] };
  }
};
