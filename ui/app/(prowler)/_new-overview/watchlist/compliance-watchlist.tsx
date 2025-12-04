"use client";

import Image, { type StaticImageData } from "next/image";
import { useState } from "react";

import { SortToggleButton } from "./_components/sort-toggle-button";
import { WatchlistCard } from "./_components/watchlist-card";

export interface ComplianceData {
  id: string;
  framework: string;
  label: string;
  icon?: string | StaticImageData;
  score: number;
}

export const ComplianceWatchlist = ({ items }: { items: ComplianceData[] }) => {
  const [isAsc, setIsAsc] = useState(true);

  const sortedItems = [...items]
    .sort((a, b) => (isAsc ? a.score - b.score : b.score - a.score))
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
      ctaLabel="Compliance Dashboard"
      ctaHref="/compliance"
      headerAction={
        <SortToggleButton
          isAscending={isAsc}
          onToggle={() => setIsAsc(!isAsc)}
          ascendingLabel="Sort by highest score"
          descendingLabel="Sort by lowest score"
        />
      }
      emptyState={{
        message: "This space is looking empty.",
        description: "to add compliance frameworks to your watchlist.",
        linkText: "Compliance Dashboard",
      }}
    />
  );
};
