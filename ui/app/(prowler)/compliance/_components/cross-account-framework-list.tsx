"use client";

import { WatchlistEmptyState } from "@/components/compliance/watchlist/watchlist-empty-state";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import { useComplianceWatchlistViewStore } from "@/store";
import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";
import {
  type KnownProviderType,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/providers";

import type { CrossAccountFrameworkEntry } from "../_types";

import { CrossAccountFrameworkCard } from "./cross-account-framework-card";

/** A framework of this section with its pinned state already resolved
 *  server-side against the catalog. */
export interface CrossAccountListEntry extends CrossAccountFrameworkEntry {
  pinned: boolean;
  watchlistEntryId: string | null;
}

export interface CrossAccountGroup {
  providerType: KnownProviderType;
  accountCount: number;
  entries: CrossAccountListEntry[];
}

interface CrossAccountFrameworkListProps {
  groups: CrossAccountGroup[];
  canManageWatchlist: boolean;
  /** False when the tenant has no catalog at all (OSS), in which case the
   *  stored filter must not be able to blank the section. */
  watchlistEnabled: boolean;
}

const GRID_CLASSES =
  "grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4";

/** Copy for the one thing this section can filter away. */
const NOTHING_PINNED_HINT =
  "No single-provider framework is pinned. Pin one from its card or the watchlist selector, or clear the filter to browse every provider type.";

/**
 * Client shell for the "across providers" catalog.
 *
 * The per-provider-type accordion is the structure of this section, filtered
 * or not: a framework here belongs to exactly one provider type, and dropping
 * that grouping would leave a flat grid of same-named frameworks (CIS for AWS,
 * CIS for Azure) with nothing to tell them apart. The filter narrows what each
 * group holds and drops the groups it empties — it never restructures the
 * section.
 */
export const CrossAccountFrameworkList = ({
  groups,
  canManageWatchlist,
  watchlistEnabled,
}: CrossAccountFrameworkListProps) => {
  const showOnlyWatchlist = useComplianceWatchlistViewStore(
    (state) => state.showOnlyWatchlist,
  );

  const renderCard = (entry: CrossAccountListEntry) => (
    <CrossAccountFrameworkCard
      key={`${entry.providerType}-${entry.complianceId}`}
      complianceId={entry.complianceId}
      title={entry.title}
      version={entry.version}
      providerType={entry.providerType}
      accountCount={entry.accountCount}
      watchlistState={
        entry.pinned ? WATCHLIST_PIN_STATE.PINNED : WATCHLIST_PIN_STATE.UNPINNED
      }
      watchlistEntryId={entry.watchlistEntryId}
      canManageWatchlist={canManageWatchlist}
    />
  );

  const filterToWatchlist = watchlistEnabled && showOnlyWatchlist;

  // A provider type with nothing pinned drops out rather than rendering an
  // accordion that expands into an empty grid.
  const visibleGroups = filterToWatchlist
    ? groups
        .map((group) => ({
          ...group,
          entries: group.entries.filter((entry) => entry.pinned),
        }))
        .filter((group) => group.entries.length > 0)
    : groups;

  if (filterToWatchlist && visibleGroups.length === 0) {
    return <WatchlistEmptyState message={NOTHING_PINNED_HINT} />;
  }

  const accordionItems: AccordionItemProps[] = visibleGroups.map((group) => ({
    key: group.providerType,
    title: (
      <span className="flex min-w-0 items-center gap-3">
        <span className="flex shrink-0 items-center gap-2 text-sm font-medium">
          <ProviderTypeIcon type={group.providerType} size={18} />
          {PROVIDER_DISPLAY_NAMES[group.providerType]}
        </span>
        <span className="text-text-neutral-tertiary truncate text-xs">
          {group.entries.length}{" "}
          {group.entries.length === 1 ? "framework" : "frameworks"} ·{" "}
          {group.accountCount} providers
        </span>
      </span>
    ),
    content: (
      <div className={GRID_CLASSES}>{group.entries.map(renderCard)}</div>
    ),
    items: [],
  }));

  return (
    <Accordion
      // Remounted when the filter flips so the expanded state is re-derived:
      // collapsed-by-default keeps a 40-framework catalog scannable, but a
      // curated list is a handful of cards that should be visible on arrival.
      key={filterToWatchlist ? "watchlist" : "catalog"}
      items={accordionItems}
      selectionMode="multiple"
      defaultExpandedKeys={
        filterToWatchlist
          ? visibleGroups.map((group) => group.providerType)
          : []
      }
    />
  );
};
