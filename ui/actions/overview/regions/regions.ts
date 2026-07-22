"use server";

import { apiBaseUrl } from "@/lib";
import { getAuthHeaders } from "@/lib/auth-headers";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { RegionsOverviewResponse } from "./types";

export const getRegionsOverview = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<RegionsOverviewResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/regions`);

  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching regions overview:", error);
    return undefined;
  }
};
