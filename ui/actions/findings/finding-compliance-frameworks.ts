"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { IN_WATCHLIST_FILTER_KEY } from "@/lib/compliance/watchlist";
import { isCloud } from "@/lib/shared/env";
import type { FindingComplianceFrameworksResult } from "@/types/compliance-watchlist";

import { adaptFindingComplianceFrameworks } from "./finding-compliance-frameworks.adapter";
import type { FindingComplianceFrameworksResponse } from "./finding-compliance-frameworks.types";

const REQUEST_TIMEOUT_MS = 10_000;

export const getFindingComplianceFrameworks = async (
  findingId: string,
  { inWatchlist = false }: { inWatchlist?: boolean } = {},
): Promise<FindingComplianceFrameworksResult> => {
  if (!findingId) return { frameworks: [], unavailable: false };
  if (!isCloud()) return { frameworks: [], unavailable: true };

  try {
    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(
      `${apiBaseUrl}/findings/${encodeURIComponent(findingId)}/compliance-frameworks`,
    );
    if (inWatchlist) {
      url.searchParams.set(IN_WATCHLIST_FILTER_KEY, "true");
    }

    const response = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { frameworks: [], unavailable: true };
    }

    const body = (await response.json()) as FindingComplianceFrameworksResponse;
    return {
      frameworks: adaptFindingComplianceFrameworks(body),
      unavailable: false,
    };
  } catch (error) {
    console.error("Error fetching the finding's compliance frameworks:", error);
    return { frameworks: [], unavailable: true };
  }
};
