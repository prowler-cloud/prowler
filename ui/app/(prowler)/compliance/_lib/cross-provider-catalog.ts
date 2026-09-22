import { WATCHLIST_SCOPE } from "@/types/compliance-watchlist";

import type { CrossProviderFrameworkEntry } from "./cross-provider-frameworks";
import { loadComplianceWatchlistContext } from "./watchlist-context";

export interface CrossProviderCatalog {
  frameworks: CrossProviderFrameworkEntry[];
  /** Empty for lack of an answer, not for lack of frameworks. */
  unavailable: boolean;
}

/**
 * Universal frameworks for the "Across providers" section, read from the API
 * catalog (`scope=universal`) so entry-point-registered ones show up too.
 * Backed by the same per-render cached request the watchlist context makes.
 */
export const loadCrossProviderFrameworks =
  async (): Promise<CrossProviderCatalog> => {
    const { entries, unavailable } = await loadComplianceWatchlistContext();

    const frameworks = entries
      .filter((entry) => entry.scope === WATCHLIST_SCOPE.UNIVERSAL)
      .map((entry) => ({
        complianceId: entry.complianceId,
        // Short name (CSA-CCM, DORA), not `name`: it keys the icon and the route.
        title: entry.framework,
        version: entry.version,
        description: entry.description,
        providerTypes: entry.providerTypes,
      }))
      .filter((entry) => entry.title.trim().length > 0)
      .sort((a, b) => a.title.localeCompare(b.title));

    return { frameworks, unavailable };
  };
