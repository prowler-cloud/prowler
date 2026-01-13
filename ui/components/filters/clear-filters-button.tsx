"use client";

import { XCircle } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { useUrlFilters } from "@/hooks/use-url-filters";

import { Button } from "../shadcn";

export interface ClearFiltersButtonProps {
  className?: string;
  text?: string;
  ariaLabel?: string;
  /** Show the count of active filters */
  showCount?: boolean;
  /** Use link style (text only, no button background) */
  variant?: "link" | "default";
}

export const ClearFiltersButton = ({
  text = "Clear all filters",
  ariaLabel = "Reset",
  showCount = false,
  variant = "link",
}: ClearFiltersButtonProps) => {
  const searchParams = useSearchParams();
  const { clearAllFilters, hasFilters } = useUrlFilters();

  // Count active filters (excluding search)
  const filterCount = Array.from(searchParams.keys()).filter(
    (key) => key.startsWith("filter[") && key !== "filter[search]",
  ).length;

  if (!hasFilters()) {
    return null;
  }

  const displayText = showCount ? `Clear Filters (${filterCount})` : text;

  return (
    <Button aria-label={ariaLabel} onClick={clearAllFilters} variant={variant}>
      <XCircle className="mr-0.5 size-4" />
      {displayText}
    </Button>
  );
};
