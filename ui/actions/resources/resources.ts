"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  parseStringify,
} from "@/lib";

export const getResources = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1)
    redirect("resources?include=findings,provider");

  const url = new URL(`${apiBaseUrl}/resources?include=findings,provider`);

  if (page) url.searchParams.append("page[number]", page.toString());

  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const resources = await fetch(url.toString(), {
      headers,
    });

    const data = await resources.json();
    const parsedData = parseStringify(data);

    revalidatePath("/resources");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching resources:", error);
    return undefined;
  }
};

export const getResourceById = async (resourceId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/resources/${resourceId}?fields[resources]=provider,region&include=findings,provider`,
  );

  try {
    const resource = await fetch(url.toString(), {
      headers,
    });
    const data = await resource.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const getResourceFields = async (fields: string, filters = {}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources`);

  url.searchParams.append("fields[resources]", fields);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const resource = await fetch(url.toString(), {
      headers,
    });
    const data = await resource.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};
