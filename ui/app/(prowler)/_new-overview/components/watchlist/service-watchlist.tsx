"use client";

import { useState } from "react";

import { ServiceOverview } from "@/actions/overview";

import { SortToggleButton } from "./sort-toggle-button";
import { WatchlistCard } from "./watchlist-card";

export const ServiceWatchlist = ({ items }: { items: ServiceOverview[] }) => {
  const [isAsc, setIsAsc] = useState(true);

  const sortedItems = [...items]
    .sort((a, b) =>
      isAsc
        ? a.attributes.fail - b.attributes.fail
        : b.attributes.fail - a.attributes.fail,
    )
    .slice(0, 5)
    .map((item) => ({
      key: item.id,
      icon: <div className="bg-bg-data-muted size-3 rounded-sm" />,
      label: item.id,
      value: item.attributes.fail,
    }));

  return (
    <WatchlistCard
      title="Service Watchlist"
      items={sortedItems}
      ctaLabel="Services Dashboard"
      ctaHref="/services"
      headerAction={
        <SortToggleButton
          isAscending={isAsc}
          onToggle={() => setIsAsc(!isAsc)}
          ascendingLabel="Sort by highest failures"
          descendingLabel="Sort by lowest failures"
        />
      }
      emptyState={{
        message: "This space is looking empty.",
        description: "to add services to your watchlist.",
        linkText: "Services Dashboard",
      }}
    />
  );
};
