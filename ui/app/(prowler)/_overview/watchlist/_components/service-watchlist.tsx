"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { ServiceOverview } from "@/actions/overview";

import { SortToggleButton } from "./sort-toggle-button";
import { WatchlistCard, WatchlistItem } from "./watchlist-card";

export const ServiceWatchlist = ({ items }: { items: ServiceOverview[] }) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isAsc, setIsAsc] = useState(false);

  const sortedItems = [...items]
    .sort((a, b) =>
      isAsc
        ? a.attributes.fail - b.attributes.fail
        : b.attributes.fail - a.attributes.fail,
    )
    .slice(0, 5)
    .map((item) => ({
      key: item.id,
      label: item.id,
      value: item.attributes.fail,
    }));

  const handleItemClick = (item: WatchlistItem) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set("filter[service__in]", item.key);
    params.set("filter[status__in]", "FAIL");
    router.push(`/findings?${params.toString()}`);
  };

  return (
    <WatchlistCard
      title="Service Watchlist"
      items={sortedItems}
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
      }}
      onItemClick={handleItemClick}
      useFailureColoring
    />
  );
};
