import { cache } from "react";

import { getComplianceCatalog } from "@/actions/compliance-watchlist";
import { auth } from "@/auth.config";
import { isCloud } from "@/lib/shared/env";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

/** Everything the three compliance surfaces need to render watchlist state:
 *  the catalog rows, the provider types the tenant may pin for, and whether
 *  the viewer is allowed to curate the list. */
export interface ComplianceWatchlistContext {
  entries: ComplianceCatalogEntry[];
  eligibleProviderTypes: string[];
  canManage: boolean;
}

export const EMPTY_WATCHLIST_CONTEXT: ComplianceWatchlistContext = {
  entries: [],
  eligibleProviderTypes: [],
  canManage: false,
};

/**
 * Resolve the watchlist context for a surface.
 *
 * Cloud-only by construction: OSS has no `/compliance-catalog` endpoint, so
 * the short-circuit means no request fires and, with an empty catalog, no
 * watchlist affordance renders either.
 *
 * Writing needs MANAGE_SCANS — the permission the watchlist endpoints are
 * actually gated on, because curating which frameworks the organization tracks
 * is compliance work rather than tenant administration. Gating this on anything
 * else renders the controls for someone the API answers 403 to, and hides them
 * from someone allowed to use them. Reading is ungated (RLS and the role's
 * provider visibility already scope the catalog server-side), which is why only
 * `canManage` depends on the session.
 *
 * Wrapped in `cache()` so the three surfaces of a single page render — the tab
 * bar's controls, the cross-provider grid and the cross-account list — share
 * one catalog instead of fetching it once each. The catalog is paginated at
 * 100, and every page re-runs the whole server-side roll-up, so the duplicates
 * were not free. `cache()` keys on argument identity, so the memoized function
 * takes the normalized provider types as a single string: two surfaces asking
 * for the same narrowed catalog would otherwise pass two distinct objects and
 * miss each other's entry.
 *
 * Never throws. `getComplianceCatalog` already degrades to an empty catalog,
 * and `auth()` is contained the same way, because a session lookup that
 * rejects must cost the page its watchlist affordances, not its compliance
 * data.
 */
const loadContextForKey = cache(
  async (providerTypesKey: string): Promise<ComplianceWatchlistContext> => {
    try {
      const providerTypes = providerTypesKey
        ? providerTypesKey.split(",")
        : undefined;

      const [catalog, session] = await Promise.all([
        getComplianceCatalog({ providerTypes }),
        auth(),
      ]);

      return {
        entries: catalog.entries,
        eligibleProviderTypes: catalog.meta.eligibleProviderTypes,
        canManage: Boolean(session?.user?.permissions?.manage_scans),
      };
    } catch (error) {
      console.error("Error loading the compliance watchlist context:", error);
      return EMPTY_WATCHLIST_CONTEXT;
    }
  },
);

/** Sorted and deduplicated so two surfaces that ask for the same provider
 *  types in a different order still share one cache entry. */
const buildProviderTypesKey = (providerTypes?: string[]): string =>
  providerTypes && providerTypes.length > 0
    ? Array.from(new Set(providerTypes)).sort().join(",")
    : "";

export const loadComplianceWatchlistContext = ({
  providerTypes,
}: {
  providerTypes?: string[];
} = {}): Promise<ComplianceWatchlistContext> => {
  if (!isCloud()) return Promise.resolve(EMPTY_WATCHLIST_CONTEXT);

  return loadContextForKey(buildProviderTypesKey(providerTypes));
};
