import type { ComplianceCatalogIndex } from "@/lib/compliance/watchlist";
import {
  isFrameworkPinned,
  resolveWatchlistEntryId,
} from "@/lib/compliance/watchlist";
import type {
  ComplianceWatchlistTarget,
  WatchlistPinState,
} from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_PIN_STATE,
} from "@/types/compliance-watchlist";

export interface UniversalWatchlistState {
  state: WatchlistPinState;
  target: ComplianceWatchlistTarget | null;
  eligibleCount: number;
  entryId: string | null;
}

interface ResolveUniversalWatchlistStateArgs {
  complianceId: string;
  compatibleProviders: string[];
  eligibleProviderTypes: string[];
  catalogIndex: ComplianceCatalogIndex;
}

export const resolveUniversalWatchlistState = ({
  complianceId,
  compatibleProviders,
  eligibleProviderTypes,
  catalogIndex,
}: ResolveUniversalWatchlistStateArgs): UniversalWatchlistState => {
  const eligible = new Set(eligibleProviderTypes);
  const eligibleCount = compatibleProviders.filter((providerType) =>
    eligible.has(providerType),
  ).length;

  const target = {
    complianceId,
    providerType: UNIVERSAL_PROVIDER_TYPE,
  };

  // A row remains removable after its last compatible provider is offboarded.
  const pinned = isFrameworkPinned(catalogIndex, target);

  return {
    state: pinned ? WATCHLIST_PIN_STATE.PINNED : WATCHLIST_PIN_STATE.UNPINNED,
    target: eligibleCount === 0 && !pinned ? null : target,
    eligibleCount,
    entryId: resolveWatchlistEntryId(catalogIndex, target),
  };
};
