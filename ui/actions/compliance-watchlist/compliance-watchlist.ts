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

// Both surfaces that render watchlist state: the compliance page and the
// overview card, which lists exactly what is pinned.
const REVALIDATED_PATHS = ["/compliance", "/"];
const CATALOG_ENDPOINT = "/compliance-catalog";
const ENTRIES_ENDPOINT = "/compliance-watchlist-entries";

// The catalog endpoint paginates at 10 by default and caps `page[size]` at
// 100, so the whole catalog of a tenant with several provider types never
// fits in one response.
const CATALOG_PAGE_SIZE = 100;
// Backstop so a malformed `meta.pagination.pages` can't spin the loop: 100
// pages is ~10k frameworks, far above any real tenant.
const MAX_CATALOG_PAGES = 100;

const EMPTY_CATALOG: ComplianceCatalog = {
  entries: [],
  meta: { totalEntries: 0, watchlistCount: 0, eligibleProviderTypes: [] },
};

const GENERIC_ERROR = "Could not update the compliance watchlist.";

// Watchlist entry IDs are UUIDs. Validate before interpolating into request
// URLs so a malformed/crafted value can't inject path segments.
const watchlistEntryIdSchema = z.uuid();

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

/**
 * The catalog of frameworks the tenant may pin, with each one's watchlist
 * state. Single source of truth for pinned state across all three compliance
 * surfaces, which join against this list on the entry's own key —
 * `(compliance_id, provider_type)`, with `*` standing in for the provider type
 * of a universal framework.
 *
 * Degrades to an empty catalog on failure — a missing catalog must hide the
 * watchlist affordances, never break the compliance page.
 */
export const getComplianceCatalog = async ({
  providerTypes,
}: {
  providerTypes?: string[];
} = {}): Promise<ComplianceCatalog> => {
  try {
    const headers = await getAuthHeaders({ contentType: false });

    // Best-effort per page: a page that fails is dropped rather than voiding
    // the whole catalog, which would hide every pinned state at once.
    const fetchPage = async (
      page: number,
    ): Promise<ComplianceCatalog | null> => {
      const pageResponse = await fetch(buildCatalogUrl(page, providerTypes), {
        headers,
      });
      if (!pageResponse.ok) return null;
      const body = (await pageResponse.json()) as ComplianceCatalogResponse;
      return adaptCatalogResponse(body);
    };

    const response = await fetch(buildCatalogUrl(1, providerTypes), {
      headers,
    });
    if (!response.ok) return EMPTY_CATALOG;

    const firstBody = (await response.json()) as ComplianceCatalogResponse;
    const firstPage = adaptCatalogResponse(firstBody);

    const pageCount = Math.min(
      Math.max(1, firstBody.meta?.pagination?.pages ?? 1),
      MAX_CATALOG_PAGES,
    );
    if (pageCount <= 1) return firstPage;

    const rest = await Promise.all(
      Array.from({ length: pageCount - 1 }, (_, index) => fetchPage(index + 2)),
    );

    return mergeCatalogPages([
      firstPage,
      ...rest.filter((page): page is ComplianceCatalog => page !== null),
    ]);
  } catch (error) {
    console.error("Error fetching compliance catalog:", error);
    return EMPTY_CATALOG;
  }
};

export const addComplianceToWatchlist = async (
  target: ComplianceWatchlistTarget,
): Promise<ComplianceWatchlistActionResult> => {
  if (!target?.complianceId?.trim() || !target?.providerType?.trim()) {
    return { error: "A framework and its provider type are required." };
  }

  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${ENTRIES_ENDPOINT}`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: COMPLIANCE_WATCHLIST_ENTRY_TYPE,
          attributes: {
            compliance_id: target.complianceId,
            provider_type: target.providerType,
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
      { method: "DELETE", headers },
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

/**
 * Apply a whole diff in one call, for the bulk modal.
 *
 * The API refuses a diff that lists the same framework in both `add` and
 * `remove` (`conflicting_target`): adds are applied first, so such a call would
 * answer 200 having changed nothing. Build both lists from catalog identities —
 * `resolveWatchlistTarget` — and that cannot happen, since two keys for one row
 * is exactly what produces the collision.
 */
export const bulkUpdateComplianceWatchlist = async (
  diff: ComplianceWatchlistBulkDiff,
): Promise<ComplianceWatchlistActionResult> => {
  if (isEmptyWatchlistDiff(diff)) {
    return { error: "Select at least one framework to add or remove." };
  }
  if (exceedsWatchlistBulkLimit(diff)) {
    return {
      error: `A single update may reference at most ${MAX_WATCHLIST_BULK} frameworks.`,
    };
  }

  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${ENTRIES_ENDPOINT}/bulk`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: COMPLIANCE_WATCHLIST_BULK_TYPE,
          attributes: {
            add: diff.add.map((target) => ({
              compliance_id: target.complianceId,
              provider_type: target.providerType,
            })),
            remove: diff.remove.map((target) => ({
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
