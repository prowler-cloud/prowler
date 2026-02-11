"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { useFilterTransitionOptional } from "@/contexts";

/**
 * Custom hook to handle URL filters and automatically reset
 * pagination when filters change.
 *
 * Uses client-side router navigation to update query params without
 * full page reloads when filters change.
 */
export const useUrlFilters = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const filterTransition = useFilterTransitionOptional();

  const navigate = (params: URLSearchParams) => {
    const queryString = params.toString();
    if (queryString === searchParams.toString()) return;

    const targetUrl = queryString ? `${pathname}?${queryString}` : pathname;
    filterTransition?.signalFilterChange();
    router.push(targetUrl, { scroll: false });
  };

  const updateFilter = (key: string, value: string | string[] | null) => {
    const params = new URLSearchParams(searchParams.toString());

    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

    const currentValue = params.get(filterKey);
    const nextValue = Array.isArray(value)
      ? value.length > 0
        ? value.join(",")
        : null
      : value === null
        ? null
        : value;

    // If effective value is unchanged, do nothing (avoids redundant fetches)
    if (currentValue === nextValue) return;

    // Always reset to first page when filters change.
    // This also guarantees a query-string change on page 1 (no existing page param).
    params.set("page", "1");

    if (nextValue === null) {
      params.delete(filterKey);
    } else {
      params.set(filterKey, nextValue);
    }

    navigate(params);
  };

  const clearFilter = (key: string) => {
    const params = new URLSearchParams(searchParams.toString());
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

    params.delete(filterKey);

    // Always reset to first page when filters change.
    params.set("page", "1");

    navigate(params);
  };

  const clearAllFilters = () => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });

    params.delete("page");

    navigate(params);
  };

  const hasFilters = () => {
    const params = new URLSearchParams(searchParams.toString());
    return Array.from(params.keys()).some(
      (key) => key.startsWith("filter[") || key === "sort",
    );
  };

  /**
   * Low-level navigation function for complex filter updates that need
   * to modify multiple params atomically (e.g., setting provider_type
   * while clearing provider_id). The modifier receives a mutable
   * URLSearchParams; page is auto-reset if already present.
   */
  const navigateWithParams = (modifier: (params: URLSearchParams) => void) => {
    const params = new URLSearchParams(searchParams.toString());
    modifier(params);

    // Always reset to first page when filters change.
    params.set("page", "1");

    navigate(params);
  };

  return {
    updateFilter,
    clearFilter,
    clearAllFilters,
    hasFilters,
    navigateWithParams,
  };
};
