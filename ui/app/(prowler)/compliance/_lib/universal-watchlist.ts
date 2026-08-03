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
  /** The pair a toggle mutates. Exactly one — or none when the card is
   *  unpinned and the tenant has no compatible provider type onboarded, which
   *  makes it unpinnable. */
  targets: ComplianceWatchlistTarget[];
  /** Onboarded provider types the card actually covers, for the caller's
   *  "covers N provider types" copy. */
  eligibleCount: number;
  /** Entry id when pinned, so unpinning uses the single-entry DELETE. */
  entryId: string | null;
}

interface ResolveUniversalWatchlistStateArgs {
  complianceId: string;
  /** Provider types the universal framework declares checks for. */
  compatibleProviders: string[];
  /** Catalog `meta.eligible_provider_types`: the types the tenant has actually
   *  onboarded and may pin for. */
  eligibleProviderTypes: string[];
  catalogIndex: ComplianceCatalogIndex;
}

/**
 * Watchlist state of a universal framework card.
 *
 * A universal framework (DORA, CSA CCM, CIS Controls) is declared by several
 * provider types but is *one* card, and the API keys it that way too: a single
 * entry under the `*` sentinel, whichever surface pinned it. So this is binary
 * — there is no per-provider-type state that could disagree with the card, and
 * no fan-out: one card, one target, one row.
 *
 * The compatible/eligible intersection still matters, but only to decide
 * whether the card is pinnable at all. A framework whose compatible types the
 * tenant has none of has nothing to aggregate, so the API refuses to pin it and
 * the caller hides the toggle.
 */
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

  // The real state is read even when no compatible provider type is left. The
  // API does not delete a pinned row when the last one is offboarded, so
  // reporting UNPINNED made the card contradict the bulk modal, which reads the
  // same catalog and still shows it ticked. `eligibleCount` decides whether the
  // framework can be pinned, never what it currently is.
  const pinned = isFrameworkPinned(catalogIndex, target);

  return {
    state: pinned ? WATCHLIST_PIN_STATE.PINNED : WATCHLIST_PIN_STATE.UNPINNED,
    // A pinned card keeps its target even with nothing eligible left, or the
    // caller would hide the only control that can unpin it and the row would
    // outlive every provider it covered. Empty targets mean "not pinnable",
    // which is only true while the card is also unpinned.
    targets: eligibleCount === 0 && !pinned ? [] : [target],
    eligibleCount,
    entryId: resolveWatchlistEntryId(catalogIndex, target),
  };
};
