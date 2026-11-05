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

const ITEMS_TO_DISPLAY = 7;

export const ComplianceWatchlist = ({
  items,
  hasWatchlist = true,
}: {
  items: ComplianceData[];
  hasWatchlist?: boolean;
}) => {
  const [isAsc, setIsAsc] = useState(true);

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
