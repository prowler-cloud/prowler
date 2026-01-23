"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { ResourceGroupOverviewResponse } from "./types";

export const getResourceGroupOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ResourceGroupOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/resource-groups`);

  // Handle multiple filters
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
    console.error("Error fetching resource group overview:", error);
    return undefined;
  }
};
