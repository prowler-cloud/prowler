"use client";

import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import { WatchlistEmptyState } from "@/components/compliance/watchlist/watchlist-empty-state";
import { useShowOnlyWatchlist } from "@/hooks/use-show-only-watchlist";
import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";

import type { UniversalWatchlistState } from "../_lib/universal-watchlist";
import type { CrossProviderFrameworkSummary } from "../_types";

import { CrossProviderFrameworkCard } from "./cross-provider-framework-card";

interface CrossProviderCard {
  summary: CrossProviderFrameworkSummary;
  watchlist: UniversalWatchlistState;
}

/** Copy for the one thing this grid can filter away. */
const NOTHING_PINNED_HINT =
  "No universal framework is pinned. Pin one from its card or the watchlist selector, or clear the filter to see them all.";

interface CrossProviderFrameworkGridProps {
  cards: CrossProviderCard[];
  /** MANAGE_SCANS, forwarded to each card's pin. */
  canManageWatchlist: boolean;
  /** False when the tenant has no catalog at all (OSS), in which case the
   *  stored filter must not be able to blank the grid. */
  watchlistEnabled: boolean;
}

/**
 * Client shell for the universal frameworks grid: the cards themselves are
 * fully resolved server-side, and this only decides which of them the stored
 * watchlist filter lets through — the filter is a viewing preference shared
 * with the other tab, so it cannot be applied during the server render.
 */
export const CrossProviderFrameworkGrid = ({
  cards,
  canManageWatchlist,
  watchlistEnabled,
}: CrossProviderFrameworkGridProps) => {
  const showOnlyWatchlist = useShowOnlyWatchlist();

  const filterToWatchlist = watchlistEnabled && showOnlyWatchlist;
  const isPinned = (card: CrossProviderCard) =>
    card.watchlist.state === WATCHLIST_PIN_STATE.PINNED;
  const visibleCards = filterToWatchlist ? cards.filter(isPinned) : cards;

  if (filterToWatchlist && visibleCards.length === 0) {
    return <WatchlistEmptyState message={NOTHING_PINNED_HINT} />;
  }

  return (
    <ComplianceFrameworkGrid>
      {visibleCards.map((card) => (
        <CrossProviderFrameworkCard
          key={card.summary.complianceId}
          {...card.summary}
          watchlist={card.watchlist}
          canManageWatchlist={canManageWatchlist}
        />
      ))}
    </ComplianceFrameworkGrid>
  );
};
