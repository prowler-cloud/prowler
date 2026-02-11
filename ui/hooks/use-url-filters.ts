"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";

/**
 * Custom hook to handle URL filters and automatically reset
 * pagination when filters change.
 *
 * Uses useTransition to prevent full page reloads when filters change,
 * keeping the current UI visible while the new data loads.
 *
 * Each instance owns its own useTransition — no shared state updates
 * during navigation. This avoids a production bug where urgent state
 * updates (from a shared context) caused re-render cascades that
 * silently aborted pending router.push transitions.
 */
export const useUrlFilters = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const [isPending, startTransition] = useTransition();

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

    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    });
  };

  const clearFilter = (key: string) => {
    const params = new URLSearchParams(searchParams.toString());
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

    params.delete(filterKey);

    // Only reset page to 1 if page parameter already exists
    if (params.has("page")) {
      params.set("page", "1");
    }

    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    });
  };

  const clearAllFilters = () => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });

    params.delete("page");

    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    });
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

    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    });
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
