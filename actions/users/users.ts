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

  const userId = formData.get("userId");
  const userName = formData.get("name");
  const userPassword = formData.get("password");
  const userEmail = formData.get("email");
  const userCompanyName = formData.get("company_name");

  const url = new URL(`${keyServer}/users/${userId}`);

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
          attributes: {
            name: userName,
            password: userPassword,
            email: userEmail,
            company_name: userCompanyName,
          },
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
