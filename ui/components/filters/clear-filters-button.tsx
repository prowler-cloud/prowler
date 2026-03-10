"use client";

import { XCircle } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

import { Button } from "../shadcn";

// Filters that should be excluded from count and visibility check
const EXCLUDED_FILTERS = ["filter[search]", "filter[muted]"];

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
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Get active filters (excluding search and muted)
  const activeFilters = Array.from(searchParams.keys()).filter(
    (key) => key.startsWith("filter[") && !EXCLUDED_FILTERS.includes(key),
  );

  const filterCount = activeFilters.length;

  // Clear all filters except excluded ones (muted, search)
  const clearFiltersPreservingExcluded = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (
        (key.startsWith("filter[") && !EXCLUDED_FILTERS.includes(key)) ||
        key === "sort"
      ) {
        params.delete(key);
      }
    });
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  }, [router, searchParams, pathname]);

  // Only show button if there are filters other than the excluded ones
  if (filterCount === 0) {
    return null;
  }

  const displayText = showCount ? `Clear Filters (${filterCount})` : text;

  return (
    <Button
      aria-label={ariaLabel}
      onClick={clearFiltersPreservingExcluded}
      variant={variant}
    >
      <XCircle className="mr-0.5 size-4" />
      {displayText}
    </Button>
  );
};
