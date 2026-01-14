"use client";

import Image, { type StaticImageData } from "next/image";
import { useState } from "react";

import { SortToggleButton } from "./sort-toggle-button";
import { WatchlistCard } from "./watchlist-card";

export interface ComplianceData {
  id: string;
  framework: string;
  label: string;
  icon?: string | StaticImageData;
  score: number;
}

// Display 7 items to match the card's min-height (405px) without scrolling
const ITEMS_TO_DISPLAY = 7;

export const ComplianceWatchlist = ({ items }: { items: ComplianceData[] }) => {
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
      ctaLabel="Explore Compliance for Each Scan"
      ctaHref="/compliance"
      headerAction={
        <SortToggleButton
          isAscending={isAsc}
          onToggle={() => setIsAsc(!isAsc)}
          ascendingLabel="Sort by highest score"
          descendingLabel="Sort by lowest score"
        />
      }
      // TODO: Enable full emptyState with description once API endpoint is implemented
      // Full emptyState: { message: "...", description: "to add compliance frameworks to your watchlist.", linkText: "Compliance Dashboard" }
      emptyState={{
        message: "No compliance data available.",
      }}
    />
  );
};
