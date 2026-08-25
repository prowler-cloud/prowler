import { cache } from "react";

import { getComplianceCatalog } from "@/actions/compliance-watchlist";
import { auth } from "@/auth.config";
import { isCloud } from "@/lib/shared/env";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

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

// One cached catalog/session lookup feeds every compliance surface in a render.
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
