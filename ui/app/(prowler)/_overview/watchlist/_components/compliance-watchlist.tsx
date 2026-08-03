"use client";

import Image, { type StaticImageData } from "next/image";
import { useState } from "react";

import {
  buildMultipleScansComplianceHref,
  buildPerScanComplianceHref,
} from "@/lib/compliance/compliance-tab-url";

import { SortToggleButton } from "./sort-toggle-button";
import { WATCHLIST_CARD_HEIGHT, WatchlistCard } from "./watchlist-card";

export interface ComplianceData {
  id: string;
  framework: string;
  label: string;
  icon?: string | StaticImageData;
  score: number;
}

// Upper bound only: the card now grows with the list, so this just keeps a
// watchlist of thirty frameworks from turning the overview into a wall.
const ITEMS_TO_DISPLAY = 7;

export const ComplianceWatchlist = ({
  items,
  hasWatchlist = true,
}: {
  items: ComplianceData[];
  /** Whether this deployment has a compliance watchlist at all.
   *
   *  With one, the list is the organization's pinned selection and the way to
   *  curate it is the Multiple Scans tab. Without one (OSS), the list is the
   *  full ranking of every framework with data, and Multiple Scans is a locked
   *  upsell tab that would bounce the visitor back to Single Scan — so both the
   *  empty state and the CTA follow this flag. */
  hasWatchlist?: boolean;
}) => {
  const [isAsc, setIsAsc] = useState(true);

  // Sort all items and take top 7 based on current sort order
  const sortedItems = [...items]
    .sort((a, b) => (isAsc ? a.score - b.score : b.score - a.score))
    .slice(0, ITEMS_TO_DISPLAY)
    .map((item) => ({
      key: item.id,
      icon: item.icon ? (
        <div className="relative size-3">
          <Image
            src={item.icon}
            alt={`${item.framework} framework`}
            fill
            className="object-contain"
          />
        </div>
      ) : (
        <div className="bg-bg-data-muted size-3 rounded-sm" />
      ),
      label: item.label,
      value: `${item.score}%`,
    }));

  return (
    <WatchlistCard
      title="Compliance Watchlist"
      items={sortedItems}
      height={WATCHLIST_CARD_HEIGHT.FIT}
      // Multiple Scans, not Single Scan: these scores are aggregated across
      // scans, and it is also where frameworks get pinned.
      ctaLabel={
        hasWatchlist
          ? "Explore Compliance for Multiple Scans"
          : "Explore Compliance for Each Scan"
      }
      ctaHref={
        hasWatchlist
          ? buildMultipleScansComplianceHref()
          : buildPerScanComplianceHref()
      }
      headerAction={
        <SortToggleButton
          isAscending={isAsc}
          onToggle={() => setIsAsc(!isAsc)}
          ascendingLabel="Sort by highest score"
          descendingLabel="Sort by lowest score"
        />
      }
      // With a watchlist, empty means "nobody pinned anything", not "no data",
      // so the way out is the compliance page. Without one there is nothing to
      // pin and empty means exactly what it used to.
      emptyState={
        hasWatchlist
          ? {
              message: "No frameworks pinned yet.",
              description: "to add compliance frameworks to your watchlist.",
              linkText: "Compliance Dashboard",
            }
          : { message: "No compliance data available." }
      }
    />
  );
};
