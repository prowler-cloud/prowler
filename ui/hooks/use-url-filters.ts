"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";

import { useFilterTransitionOptional } from "@/contexts";

/**
 * Custom hook to handle URL filters and automatically reset
 * pagination when filters change.
 *
 * Uses useTransition to prevent full page reloads when filters change,
 * keeping the current UI visible while the new data loads.
 *
 * When used within a FilterTransitionProvider, the transition state is shared
 * across all components using this hook, enabling coordinated loading indicators.
 */
export const useUrlFilters = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pathname = usePathname();

  // Signal shared pending state for DataTable loading indicator
  const filterTransition = useFilterTransitionOptional();
  const [localIsPending, startTransition] = useTransition();

  const isPending = filterTransition?.isPending ?? localIsPending;

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

    filterTransition?.signalFilterChange();
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

    filterTransition?.signalFilterChange();
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

    filterTransition?.signalFilterChange();
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

  return {
    updateFilter,
    clearFilter,
    clearAllFilters,
    hasFilters,
    isPending,
  };
};
