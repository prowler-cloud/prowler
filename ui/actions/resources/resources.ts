"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";

export const getResources = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
  include = "",
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("resources");

  const url = new URL(`${apiBaseUrl}/resources`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (include) url.searchParams.append("include", include);

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
    console.error("Error fetching resources:", error);
    return undefined;
  }
};

export const getLatestResources = async ({
  page = 1,
  query = "",
  sort = "",
  include = "",
  filters = {},
  pageSize = 10,
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("resources");

  const url = new URL(`${apiBaseUrl}/resources/latest`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (include) url.searchParams.append("include", include);

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
    console.error("Error fetching latest resources:", error);
    return undefined;
  }
};

export const getMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources/metadata`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const metadata = await fetch(url.toString(), {
      headers,
    });

    const data = await metadata.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching metadata info:", error);
    return undefined;
  }
};

export const getLatestMetadataInfo = async ({
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources/metadata/latest`);

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const metadata = await fetch(url.toString(), {
      headers,
    });

    const data = await metadata.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    console.error("Error fetching latest metadata info:", error);
    return undefined;
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
    console.error("Error fetching resource fields:", error);
    return undefined;
  }
};

export const getResourceById = async (
  id: string,
  {
    fields = [],
    include = [],
  }: {
    fields?: string[];
    include?: string[];
  } = {},
) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources/${id}`);

  if (fields.length > 0) {
    url.searchParams.append("fields[resources]", fields.join(","));
  }

  if (include.length > 0) {
    url.searchParams.append("include", include.join(","));
  }

  try {
    const resource = await fetch(url.toString(), {
      headers,
    });

    if (!resource.ok) {
      throw new Error(`Error fetching resource: ${resource.status}`);
    }

    const data = await resource.json();
    const parsedData = parseStringify(data);

    return parsedData;
  } catch (error) {
    console.error("Error fetching resource by ID:", error);
    return undefined;
  }
};
