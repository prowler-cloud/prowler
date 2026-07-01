"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { ComplianceWatchlistResponse } from "./compliance-watchlist.types";

export const getComplianceWatchlist = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ComplianceWatchlistResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/overviews/compliance-watchlist`);

  // Append filter parameters (provider_id, provider_type, etc.)
  // Exclude filter[search] as this endpoint doesn't support text search
  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance watchlist:", error);
    return undefined;
  }
};
