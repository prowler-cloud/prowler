"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
<<<<<<< HEAD
import { useCallback, useTransition } from "react";

import { useFilterTransitionOptional } from "@/contexts";
=======
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))

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
  const isPending = false;

<<<<<<< HEAD
  // Use shared context if available, otherwise fall back to local transition
  const sharedTransition = useFilterTransitionOptional();
  const [localIsPending, localStartTransition] = useTransition();

  const isPending = sharedTransition?.isPending ?? localIsPending;
  const startTransition =
    sharedTransition?.startTransition ?? localStartTransition;
=======
  const navigate = (params: URLSearchParams) => {
    const queryString = params.toString();
    const targetUrl = queryString ? `${pathname}?${queryString}` : pathname;
    router.push(targetUrl, { scroll: false });
  };
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))

  const updateFilter = useCallback(
    (key: string, value: string | string[] | null) => {
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
    },
    [router, searchParams, pathname, startTransition],
  );

  const clearFilter = useCallback(
    (key: string) => {
      const params = new URLSearchParams(searchParams.toString());
      const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;

      params.delete(filterKey);

<<<<<<< HEAD
      // Only reset page to 1 if page parameter already exists
      if (params.has("page")) {
        params.set("page", "1");
      }
=======
    navigate(params);
  };
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))

      startTransition(() => {
        router.push(`${pathname}?${params.toString()}`, { scroll: false });
      });
    },
    [router, searchParams, pathname, startTransition],
  );

<<<<<<< HEAD
  const clearAllFilters = useCallback(() => {
=======
    params.delete(filterKey);

    // Only reset page to 1 if page parameter already exists
    if (params.has("page")) {
      params.set("page", "1");
    }

    navigate(params);
  };

  const clearAllFilters = () => {
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });

    params.delete("page");

<<<<<<< HEAD
    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    });
  }, [router, searchParams, pathname, startTransition]);
=======
    navigate(params);
  };
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))

  const hasFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    return Array.from(params.keys()).some(
      (key) => key.startsWith("filter[") || key === "sort",
    );
<<<<<<< HEAD
  }, [searchParams]);
=======
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
>>>>>>> bcd7b2d72 (fix(ui): remove useTransition and shared context from useUrlFilters (#10025))

  return {
    updateFilter,
    clearFilter,
    clearAllFilters,
    hasFilters,
    isPending,
  };
};
