"use client";

import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import { WatchlistEmptyState } from "@/components/compliance/watchlist/watchlist-empty-state";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import { useShowOnlyWatchlist } from "@/hooks/use-show-only-watchlist";
import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";
import {
  type KnownProviderType,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/providers";

import type { CrossAccountFrameworkEntry } from "../_types";

import { CrossAccountFrameworkCard } from "./cross-account-framework-card";

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
  watchlistEnabled: boolean;
}

const NOTHING_PINNED_HINT =
  "No single-provider framework is pinned. Pin one from its card or the watchlist selector, or clear the filter to browse every provider type.";

export const CrossAccountFrameworkList = ({
  groups,
  canManageWatchlist,
  watchlistEnabled,
}: CrossAccountFrameworkListProps) => {
  const showOnlyWatchlist = useShowOnlyWatchlist();

  const renderCard = (entry: CrossAccountListEntry) => (
    <CrossAccountFrameworkCard
      key={`${entry.providerType}-${entry.complianceId}`}
      complianceId={entry.complianceId}
      title={entry.title}
      version={entry.version}
      providerType={entry.providerType}
      accountCount={entry.accountCount}
      watchlistState={
        watchlistEnabled
          ? entry.pinned
            ? WATCHLIST_PIN_STATE.PINNED
            : WATCHLIST_PIN_STATE.UNPINNED
          : undefined
      }
      watchlistEntryId={entry.watchlistEntryId}
      canManageWatchlist={canManageWatchlist}
    />
  );

  const filterToWatchlist = watchlistEnabled && showOnlyWatchlist;

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
      <ComplianceFrameworkGrid>
        {group.entries.map(renderCard)}
      </ComplianceFrameworkGrid>
    ),
    items: [],
  }));

  return (
    <Accordion
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
