"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, handleApiResponse } from "@/lib";

export const getResources = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
  include = "",
  fields = [],
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string>;
  pageSize?: number;
  include?: string;
  fields?: string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("resources");

  const url = new URL(`${apiBaseUrl}/resources`);

  if (fields.length > 0) {
    url.searchParams.append("fields[resources]", fields.join(","));
  }

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (include) url.searchParams.append("include", include);
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response, "/resources");
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
  fields = [],
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string>;
  pageSize?: number;
  include?: string;
  fields?: string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("resources");

  const url = new URL(`${apiBaseUrl}/resources/latest`);

  if (fields.length > 0) {
    url.searchParams.append("fields[resources]", fields.join(","));
  }

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (include) url.searchParams.append("include", include);
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response, "/resources");
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
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
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
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching latest metadata info:", error);
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

    return handleApiResponse(resource);
  } catch (error) {
    console.error("Error fetching resource by ID:", error);
    return undefined;
  }
};
