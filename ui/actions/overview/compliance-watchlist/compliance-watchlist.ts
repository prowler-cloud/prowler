"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { IN_WATCHLIST_FILTER_KEY } from "@/lib/compliance/watchlist";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";
import type { ApiResult } from "@/types/server-actions";

import { ComplianceWatchlistResponse } from "./compliance-watchlist.types";

interface ComplianceWatchlistInput {
  filters?: Record<string, string | string[] | undefined>;
  inWatchlist?: boolean;
}

const complianceWatchlistInputSchema = z.object({
  filters: z
    .record(
      z.string(),
      z.union([z.string(), z.array(z.string()), z.undefined()]),
    )
    .default({}),
  inWatchlist: z.boolean().default(false),
});

export const getComplianceWatchlist = async (
  input: ComplianceWatchlistInput = {},
): Promise<ApiResult<ComplianceWatchlistResponse> | undefined> => {
  const parsedInput = complianceWatchlistInputSchema.safeParse(input);
  if (!parsedInput.success) return undefined;

  const { filters, inWatchlist } = parsedInput.data;
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/overviews/compliance-watchlist`);

  // Append filter parameters (provider_id, provider_type, etc.)
  // Exclude filter[search] as this endpoint doesn't support text search
  appendSanitizedProviderTypeFilters(url, filters);

  if (inWatchlist) {
    url.searchParams.set(IN_WATCHLIST_FILTER_KEY, "true");
  }

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance watchlist:", error);
    return undefined;
  }
};
