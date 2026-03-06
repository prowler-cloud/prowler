"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { CategoryOverviewResponse } from "./types";

export const getCategoryOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<CategoryOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/categories`);

  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching category overview:", error);
    return undefined;
  }
};
