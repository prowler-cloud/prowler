"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  parseStringify,
} from "@/lib";

export const getUsers = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/users?include=roles");

  const url = new URL(`${apiBaseUrl}/users?include=roles`);

  if (page) url.searchParams.append("page[number]", page.toString());
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
    const data = await users.json();
    const parsedData = parseStringify(data);
    revalidatePath("/users");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching users:", error);
    return undefined;
  }
};

export const updateUser = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const userId = formData.get("userId") as string; // Ensure userId is a string
  const userName = formData.get("name") as string | null;
  const userPassword = formData.get("password") as string | null;
  const userEmail = formData.get("email") as string | null;
  const userCompanyName = formData.get("company_name") as string | null;

  const url = new URL(`${apiBaseUrl}/users/${userId}`);

  // Prepare attributes to send based on changes
  const attributes: Record<string, any> = {};

  // Add only changed fields
  if (userName !== null) attributes.name = userName;
  if (userEmail !== null) attributes.email = userEmail;
  if (userCompanyName !== null) attributes.company_name = userCompanyName;
  if (userPassword !== null) attributes.password = userPassword;

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

    const data = await response.json();
    revalidatePath("/users");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateUserRole = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const userId = formData.get("userId") as string;
  const roleId = formData.get("roleId") as string;

  // Validate required fields
  if (!userId || !roleId) {
    return { error: "userId and roleId are required" };
  }

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

    const data = await response.json();

    if (!response.ok) {
      return { error: data.errors || "An error occurred" };
    }

    revalidatePath("/users"); // Update the path as needed
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteUser = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const userId = formData.get("userId");

  if (!userId) {
    return { error: "User ID is required" };
  }

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
    // eslint-disable-next-line no-console
    console.error("Error deleting user:", error);
    return { error: getErrorMessage(error) };
  }
};

export const getProfileInfo = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/users/me`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user data: ${response.statusText}`);
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/profile");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching profile:", error);
    return undefined;
  }
};
