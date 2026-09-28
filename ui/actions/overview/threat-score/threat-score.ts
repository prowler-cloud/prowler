"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";
import type { ApiResult } from "@/types/server-actions";

import type { ThreatScoreResponse } from "./types";

export const getThreatScore = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<ApiResult<ThreatScoreResponse> | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/threatscore`);

  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching threat score:", error);
    return undefined;
  }
};
