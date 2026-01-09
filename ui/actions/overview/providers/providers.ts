"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { ProvidersOverviewResponse } from "./types";

export const getProvidersOverview = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
}: {
  page?: number;
  query?: string;
  sort?: string;
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ProvidersOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers-overview");

  const url = new URL(`${apiBaseUrl}/overviews/providers`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]" && value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching providers overview:", error);
    return undefined;
  }
};
