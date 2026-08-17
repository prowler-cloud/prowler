"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import {
  exceedsWatchlistBulkLimit,
  formatWatchlistBulkSummary,
  isEmptyWatchlistDiff,
  MAX_WATCHLIST_BULK,
} from "@/lib/compliance/watchlist";
import type {
  ComplianceCatalog,
  ComplianceWatchlistActionResult,
  ComplianceWatchlistBulkDiff,
  ComplianceWatchlistTarget,
} from "@/types/compliance-watchlist";
import {
  COMPLIANCE_WATCHLIST_BULK_TYPE,
  COMPLIANCE_WATCHLIST_ENTRY_TYPE,
} from "@/types/compliance-watchlist";

import {
  adaptCatalogResponse,
  adaptWatchlistBulkSummary,
  mergeCatalogPages,
} from "./compliance-watchlist.adapter";
import type {
  ComplianceCatalogResponse,
  ComplianceWatchlistBulkResponse,
} from "./compliance-watchlist.types";

const REVALIDATED_PATHS = ["/compliance", "/"];
const CATALOG_ENDPOINT = "/compliance-catalog";
const ENTRIES_ENDPOINT = "/compliance-watchlist-entries";

const CATALOG_PAGE_SIZE = 100;
const MAX_CATALOG_PAGES = 100;
const CATALOG_FETCH_CONCURRENCY = 5;
const REQUEST_TIMEOUT_MS = 15_000;

const EMPTY_CATALOG: ComplianceCatalog = {
  entries: [],
  meta: { totalEntries: 0, watchlistCount: 0, eligibleProviderTypes: [] },
};

const GENERIC_ERROR = "Could not update the compliance watchlist.";

const watchlistTargetSchema = z.object({
  complianceId: z.string().trim().min(1),
  providerType: z.string().trim().min(1),
});
const complianceCatalogInputSchema = z.object({
  providerTypes: z.array(z.string().trim().min(1)).optional(),
});
const complianceWatchlistBulkDiffSchema = z.object({
  add: z.array(watchlistTargetSchema),
  remove: z.array(watchlistTargetSchema),
});
const watchlistEntryIdSchema = z.uuid();

interface CatalogPageResult {
  catalog: ComplianceCatalog;
  pageCount: number;
}

/** Pull the API's user-facing error detail out of a JSON:API error document.
 *  Anything unparseable (5xx, HTML error pages) collapses into a generic
 *  message so no internals reach the user. */
const readApiError = async (
  response: Response,
  fallback: string,
): Promise<string> => {
  try {
    const body = await response.json();
    const detail = Array.isArray(body?.errors)
      ? body.errors[0]?.detail || body.errors[0]?.title
      : undefined;
    return typeof detail === "string" && detail.trim().length > 0
      ? detail
      : fallback;
  } catch {
    return fallback;
  }
};

const buildCatalogUrl = (page: number, providerTypes?: string[]): string => {
  const url = new URL(`${apiBaseUrl}${CATALOG_ENDPOINT}`);
  url.searchParams.set("page[size]", String(CATALOG_PAGE_SIZE));
  url.searchParams.set("page[number]", String(page));
  if (providerTypes && providerTypes.length > 0) {
    url.searchParams.set("filter[provider_type__in]", providerTypes.join(","));
  }
  return url.toString();
};

export const getComplianceCatalog = async (
  input: { providerTypes?: string[] } = {},
): Promise<ComplianceCatalog> => {
  const parsedInput = complianceCatalogInputSchema.safeParse(input);
  if (!parsedInput.success) return EMPTY_CATALOG;

  const { providerTypes } = parsedInput.data;

  try {
    const headers = await getAuthHeaders({ contentType: false });

    const fetchPage = async (
      page: number,
    ): Promise<CatalogPageResult | null> => {
      try {
        const pageResponse = await fetch(buildCatalogUrl(page, providerTypes), {
          headers,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (!pageResponse.ok) return null;
        const body = (await pageResponse.json()) as ComplianceCatalogResponse;
        return {
          catalog: adaptCatalogResponse(body),
          pageCount: body.meta?.pagination?.pages ?? 1,
        };
      } catch (error) {
        console.error(`Error fetching compliance catalog page ${page}:`, error);
        return null;
      }
    };

    const firstPage = await fetchPage(1);
    if (!firstPage) return EMPTY_CATALOG;

    const pageCount = Math.min(
      Math.max(1, firstPage.pageCount),
      MAX_CATALOG_PAGES,
    );
    if (pageCount <= 1) return firstPage.catalog;

    const rest: ComplianceCatalog[] = [];
    for (let page = 2; page <= pageCount; page += CATALOG_FETCH_CONCURRENCY) {
      const batch = await Promise.all(
        Array.from(
          { length: Math.min(CATALOG_FETCH_CONCURRENCY, pageCount - page + 1) },
          (_, index) => fetchPage(page + index),
        ),
      );
      rest.push(...batch.flatMap((page) => (page ? [page.catalog] : [])));
    }

    return mergeCatalogPages([firstPage.catalog, ...rest]);
  } catch (error) {
    console.error("Error fetching compliance catalog:", error);
    return EMPTY_CATALOG;
  }
};

export const addComplianceToWatchlist = async (
  target: ComplianceWatchlistTarget,
): Promise<ComplianceWatchlistActionResult> => {
  const parsedTarget = watchlistTargetSchema.safeParse(target);
  if (!parsedTarget.success) {
    return { error: "A framework and its provider type are required." };
  }

  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${ENTRIES_ENDPOINT}`, {
      method: "POST",
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      body: JSON.stringify({
        data: {
          type: COMPLIANCE_WATCHLIST_ENTRY_TYPE,
          attributes: {
            compliance_id: parsedTarget.data.complianceId,
            provider_type: parsedTarget.data.providerType,
          },
        },
      }),
    });

    if (!response.ok) {
      return {
        error: await readApiError(
          response,
          "Could not add the framework to the watchlist.",
        ),
      };
    }

    REVALIDATED_PATHS.forEach((path) => revalidatePath(path));
    return { success: "Added to watchlist." };
  } catch (error) {
    console.error("Error adding framework to the watchlist:", error);
    return { error: GENERIC_ERROR };
  }
};

export const removeComplianceFromWatchlist = async (
  entryId: string,
): Promise<ComplianceWatchlistActionResult> => {
  const parsed = watchlistEntryIdSchema.safeParse(entryId);
  if (!parsed.success) {
    return { error: "Invalid watchlist entry." };
  }

  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(
      `${apiBaseUrl}${ENTRIES_ENDPOINT}/${parsed.data}`,
      {
        method: "DELETE",
        headers,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );

    if (!response.ok) {
      return {
        error: await readApiError(
          response,
          "Could not remove the framework from the watchlist.",
        ),
      };
    }

    REVALIDATED_PATHS.forEach((path) => revalidatePath(path));
    return { success: "Removed from watchlist." };
  } catch (error) {
    console.error("Error removing framework from the watchlist:", error);
    return { error: GENERIC_ERROR };
  }
};

export const bulkUpdateComplianceWatchlist = async (
  diff: ComplianceWatchlistBulkDiff,
): Promise<ComplianceWatchlistActionResult> => {
  const parsedDiff = complianceWatchlistBulkDiffSchema.safeParse(diff);
  if (!parsedDiff.success) {
    return { error: "Invalid compliance watchlist update." };
  }

  if (isEmptyWatchlistDiff(parsedDiff.data)) {
    return { error: "Select at least one framework to add or remove." };
  }
  if (exceedsWatchlistBulkLimit(parsedDiff.data)) {
    return {
      error: `A single update may reference at most ${MAX_WATCHLIST_BULK} frameworks.`,
    };
  }

  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${ENTRIES_ENDPOINT}/bulk`, {
      method: "POST",
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      body: JSON.stringify({
        data: {
          type: COMPLIANCE_WATCHLIST_BULK_TYPE,
          attributes: {
            add: parsedDiff.data.add.map((target) => ({
              compliance_id: target.complianceId,
              provider_type: target.providerType,
            })),
            remove: parsedDiff.data.remove.map((target) => ({
              compliance_id: target.complianceId,
              provider_type: target.providerType,
            })),
          },
        },
      }),
    });

    if (!response.ok) {
      return { error: await readApiError(response, GENERIC_ERROR) };
    }

    const body = (await response.json()) as ComplianceWatchlistBulkResponse;
    const summary = adaptWatchlistBulkSummary(body);

    REVALIDATED_PATHS.forEach((path) => revalidatePath(path));
    return { success: formatWatchlistBulkSummary(summary), summary };
  } catch (error) {
    console.error("Error updating the compliance watchlist:", error);
    return { error: GENERIC_ERROR };
  }
};
