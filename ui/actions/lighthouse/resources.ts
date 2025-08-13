import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib/helper";

export async function getLighthouseResources({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  fields = [],
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: any;
  fields?: string[];
}) {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources`);

  if (page) {
    url.searchParams.append("page[number]", page.toString());
  }

  if (sort) {
    url.searchParams.append("sort", sort);
  }

  if (query) {
    url.searchParams.append("filter[search]", query);
  }

  if (fields.length > 0) {
    url.searchParams.append("fields[resources]", fields.join(","));
  }

  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      url.searchParams.append(`${key}`, value as string);
    }
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
    });
    const data = await response.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    console.error("Error fetching resources:", error);
    return undefined;
  }
}

export async function getLighthouseLatestResources({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  fields = [],
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: any;
  fields?: string[];
}) {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/resources/latest`);

  if (page) {
    url.searchParams.append("page[number]", page.toString());
  }

  if (sort) {
    url.searchParams.append("sort", sort);
  }

  if (query) {
    url.searchParams.append("filter[search]", query);
  }

  if (fields.length > 0) {
    url.searchParams.append("fields[resources]", fields.join(","));
  }

  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      url.searchParams.append(`${key}`, value as string);
    }
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
    });
    const data = await response.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    console.error("Error fetching resources:", error);
    return undefined;
  }
}

export async function getLighthouseResourceById({
  id,
  fields = [],
  include = [],
}: {
  id: string;
  fields?: string[];
  include?: string[];
}) {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/resources/${id}`);

  if (fields.length > 0) {
    url.searchParams.append("fields", fields.join(","));
  }

  if (include.length > 0) {
    url.searchParams.append("include", include.join(","));
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
    });
    const data = await response.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    console.error("Error fetching resource:", error);
    return undefined;
  }
}
