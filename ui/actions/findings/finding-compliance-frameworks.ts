"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { IN_WATCHLIST_FILTER_KEY } from "@/lib/compliance/watchlist";
import { isCloud } from "@/lib/shared/env";
import type { FindingComplianceFrameworksResult } from "@/types/compliance-watchlist";

import { adaptFindingComplianceFrameworks } from "./finding-compliance-frameworks.adapter";
import type { FindingComplianceFrameworksResponse } from "./finding-compliance-frameworks.types";

const REQUEST_TIMEOUT_MS = 10_000;
const findingIdSchema = z.string().trim().min(1);
const findingComplianceFrameworkOptionsSchema = z.object({
  inWatchlist: z.boolean().optional(),
});

export const getFindingComplianceFrameworks = async (
  findingId: string,
  options: { inWatchlist?: boolean } = {},
): Promise<FindingComplianceFrameworksResult> => {
  const parsedFindingId = findingIdSchema.safeParse(findingId);
  if (!parsedFindingId.success) {
    return { frameworks: [], unavailable: false };
  }

  const parsedOptions =
    findingComplianceFrameworkOptionsSchema.safeParse(options);
  if (!parsedOptions.success) {
    return { frameworks: [], unavailable: true };
  }

  const { inWatchlist = false } = parsedOptions.data;
  if (!isCloud()) return { frameworks: [], unavailable: true };

  try {
    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(
      `${apiBaseUrl}/findings/${encodeURIComponent(parsedFindingId.data)}/compliance-frameworks`,
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
