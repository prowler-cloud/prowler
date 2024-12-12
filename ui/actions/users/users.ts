"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { auth } from "@/auth.config";
import { getErrorMessage, parseStringify, wait } from "@/lib";

export const getUsers = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const session = await auth();

  if (isNaN(Number(page)) || page < 1) redirect("/users");

  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/users`);

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
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await users.json();
    const parsedData = parseStringify(data);
    revalidatePath("/users");
    return parsedData;
  } catch (error) {
    console.error("Error fetching users:", error);
    return undefined;
  }
};

export const updateUser = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const userId = formData.get("userId") as string; // Ensure userId is a string
  const userName = formData.get("name") as string | null;
  const userPassword = formData.get("password") as string | null;
  const userEmail = formData.get("email") as string | null;
  const userCompanyName = formData.get("company_name") as string | null;

  const url = new URL(`${keyServer}/users/${userId}`);

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
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
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
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const deleteUser = async (formData: FormData) => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;

  const userId = formData.get("userId");
  const url = new URL(`${keyServer}/users/${userId}`);
  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });
    const data = await response.json();
    await wait(1000);
    revalidatePath("/users");
    return parseStringify(data);
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getProfileInfo = async () => {
  const session = await auth();
  const keyServer = process.env.API_BASE_URL;
  const url = new URL(`${keyServer}/users/me`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Accept: "application/vnd.api+json",
        Authorization: `Bearer ${session?.accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user data: ${response.statusText}`);
    }

    const data = await response.json();
    const parsedData = parseStringify(data);
    revalidatePath("/profile");
    return parsedData;
  } catch (error) {
    console.error("Error fetching profile:", error);
    return undefined;
  }
};
