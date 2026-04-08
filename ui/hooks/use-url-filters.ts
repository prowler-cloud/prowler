"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { useFilterTransitionOptional } from "@/contexts";

const FINDINGS_PATH = "/findings";
const DEFAULT_MUTED_FILTER = "false";

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
  const isPending = false;

  const ensureFindingsDefaultMuted = (params: URLSearchParams) => {
    // Findings defaults to excluding muted findings unless user sets it explicitly.
    if (pathname === FINDINGS_PATH && !params.has("filter[muted]")) {
      params.set("filter[muted]", DEFAULT_MUTED_FILTER);
    }
  };

  const navigate = (params: URLSearchParams) => {
    ensureFindingsDefaultMuted(params);

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

    // Only reset page to 1 if page parameter already exists
    if (params.has("page")) {
      params.set("page", "1");
    }

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

    // Only reset page to 1 if page parameter already exists
    if (params.has("page")) {
      params.set("page", "1");
    }

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

    // Only reset page to 1 if page parameter already exists
    if (params.has("page")) {
      params.set("page", "1");
    }

    navigate(params);
  };

  return {
    updateFilter,
    clearFilter,
    clearAllFilters,
    hasFilters,
    isPending,
    navigateWithParams,
  };
};
