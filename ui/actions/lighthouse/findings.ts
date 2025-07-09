"use server";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";

export const getLighthouseFindings = async ({
  page = 1,
  pageSize = 10,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  // For lighthouse usage, handle invalid page numbers by defaulting to 1
  const validPage = isNaN(Number(page)) || page < 1 ? 1 : page;

  const url = new URL(`${apiBaseUrl}/findings`);

  if (validPage) url.searchParams.append("page[number]", validPage.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });
    const data = await findings.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching lighthouse findings:", error);
    return undefined;
  }
};

export const getLighthouseLatestFindings = async ({
  page = 1,
  pageSize = 10,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const validPage = isNaN(Number(page)) || page < 1 ? 1 : page;

  const url = new URL(`${apiBaseUrl}/findings/latest`);

  if (validPage) url.searchParams.append("page[number]", validPage.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());

  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  try {
    const findings = await fetch(url.toString(), {
      headers,
    });
    const data = await findings.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching lighthouse latest findings:", error);
    return undefined;
  }
};
