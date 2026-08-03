"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { IN_WATCHLIST_FILTER_KEY } from "@/lib/compliance/watchlist";
import { isCloud } from "@/lib/shared/env";

import { adaptFindingComplianceFrameworks } from "./finding-compliance-frameworks.adapter";
import type {
  FindingComplianceFrameworksResponse,
  FindingComplianceFrameworksResult,
} from "./finding-compliance-frameworks.types";

const REQUEST_TIMEOUT_MS = 10_000;

/**
 * The compliance frameworks whose requirements include this finding's check.
 *
 * Resolved by the API from the SDK's check-to-framework mapping, so it does not
 * depend on compliance data having been aggregated for the scan. Each entry
 * carries its `complianceId`, which is what makes a click navigate straight to
 * the framework instead of matching the display name against the scan's
 * overview.
 *
 * `unavailable` separates "this deployment has no such endpoint" from "the
 * watchlist is empty". Both come back as no frameworks, but only the first one
 * means the caller should fall back to the check's own metadata: the endpoint
 * is Cloud-only, so on a self-hosted install it 404s, and treating that as an
 * empty watchlist would delete the strip for every finding.
 *
 * Which is why OSS short-circuits rather than discovering that by 404ing: the
 * drawer asks once per finding opened, and none of those requests can ever
 * succeed there.
 */
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

    // The drawer awaits this before it can paint the compliance strip, so a
    // stalled API has to surface as `unavailable` — the fallback path — rather
    // than leaving the strip pending for as long as the socket stays open.
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
