"use client";

import { ArrowDownNarrowWide, ArrowUpNarrowWide } from "lucide-react";
import Image, { type StaticImageData } from "next/image";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";

import { WatchlistCard } from "./watchlist-card";

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

  const SortIcon = isAsc ? ArrowUpNarrowWide : ArrowDownNarrowWide;

  return (
    <WatchlistCard
      title="Compliance Watchlist"
      items={sortedItems}
      ctaLabel="Compliance Dashboard"
      ctaHref="/compliance"
      headerAction={
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsAsc(!isAsc)}
          aria-label={isAsc ? "Sort by highest score" : "Sort by lowest score"}
        >
          <SortIcon className="size-4" />
        </Button>
      }
      emptyState={{
        message: "This space is looking empty.",
        description: "to add compliance frameworks to your watchlist.",
        linkText: "Compliance Dashboard",
      }}
    />
  );
};
