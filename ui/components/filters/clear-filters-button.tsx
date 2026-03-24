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
  /**
   * Optional callback for batch mode. When provided, this is called INSTEAD
   * of pushing URL params directly. Useful for clearing pending filter state
   * without immediately navigating.
   */
  onClear?: () => void;
  /**
   * In batch mode, the number of pending filter keys that have non-empty values.
   * When provided alongside `onClear`, overrides the URL-based count shown by
   * `showCount`. This ensures the displayed count reflects the pending state
   * (not the last-applied URL state) while the user is editing filters.
   */
  pendingCount?: number;
}

export const ClearFiltersButton = ({
  text = "Clear all filters",
  ariaLabel = "Reset",
  showCount = false,
  variant = "link",
  onClear,
  pendingCount,
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

  // In batch mode: use pendingCount if provided; otherwise fall back to URL count.
  // In instant mode: always use URL count.
  const displayCount =
    onClear && pendingCount !== undefined ? pendingCount : filterCount;

  // In instant mode: hide when no URL filters exist
  if (!onClear && filterCount === 0) {
    return null;
  }

  // In batch mode: hide when there are no pending or URL filters to clear
  if (onClear && displayCount === 0) {
    return null;
  }

  const displayText = showCount ? `Clear Filters (${displayCount})` : text;

  return (
    <Button
      aria-label={ariaLabel}
      onClick={onClear ?? clearFiltersPreservingExcluded}
      variant={variant}
    >
      <XCircle className="mr-0.5 size-4" />
      {displayText}
    </Button>
  );
};
