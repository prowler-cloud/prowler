"use server";
import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, handleApiResponse } from "@/lib";

export const getProvidersOverview = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers-overview");

  const url = new URL(`${apiBaseUrl}/overviews/providers`);

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
    const response = await fetch(url.toString(), {
      headers,
    });

    handleApiResponse(response, "/");
  } catch (error) {
    console.error("Error fetching providers overview:", error);
    return undefined;
  }
};

export const getFindingsByStatus = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const url = new URL(`${apiBaseUrl}/overviews/findings`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters, but exclude muted filter as overviews endpoint doesn't support it
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && key !== "filter[muted]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    handleApiResponse(response, "/");
  } catch (error) {
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};

export const getFindingsBySeverity = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/");

  const url = new URL(`${apiBaseUrl}/overviews/findings_severity`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters, but exclude muted filter as overviews endpoint doesn't support it
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && key !== "filter[muted]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    handleApiResponse(response, "/");
  } catch (error) {
    console.error("Error fetching findings severity overview:", error);
    return undefined;
  }
};
