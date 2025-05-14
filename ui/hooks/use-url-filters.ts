"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

/**
 * Custom hook to handle URL filters and automatically reset
 * pagination when filters change.
 */
export const useUrlFilters = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pathname = usePathname();

  const updateFilter = useCallback(
    (key: string, value: string | string[] | null) => {
      const params = new URLSearchParams(searchParams.toString());

      // Always reset page to 1 when a filter is applied
      params.set("page", "1");

      const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

      if (value === null || (Array.isArray(value) && value.length === 0)) {
        params.delete(filterKey);
      } else if (Array.isArray(value)) {
        params.set(filterKey, value.join(","));
      } else {
        params.set(filterKey, value);
      }

      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [router, searchParams, pathname],
  );

  const clearFilter = useCallback(
    (key: string) => {
      const params = new URLSearchParams(searchParams.toString());
      const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

      params.delete(filterKey);
      params.set("page", "1");

      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [router, searchParams, pathname],
  );

  const clearAllFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });

    params.delete("page");

    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  }, [router, searchParams, pathname]);

  return {
    updateFilter,
    clearFilter,
    clearAllFilters,
  };
};
