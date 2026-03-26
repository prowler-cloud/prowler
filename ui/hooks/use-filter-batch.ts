"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

// Filters that are managed by the batch hook (excludes system defaults)
const EXCLUDED_FROM_BATCH = ["filter[search]"];

/**
 * Snapshot of pending (un-applied) filter state.
 * Keys are raw filter param names, e.g. "filter[severity__in]".
 * Values are arrays of selected option strings.
 */
export interface PendingFilters {
  [filterKey: string]: string[];
}

export interface UseFilterBatchReturn {
  /** Current pending filter values — local state, not yet in URL */
  pendingFilters: PendingFilters;
  /** Update a single pending filter. Does NOT touch the URL. */
  setPending: (key: string, values: string[]) => void;
  /** Apply all pending filters to URL in a single router.push */
  applyAll: () => void;
  /** Discard all pending changes, reset pending to the current URL state */
  discardAll: () => void;
  /**
   * Clear all pending filters to an empty state (no filters selected).
   * Unlike `discardAll`, this does NOT reset to the URL state — it sets
   * pending to `{}` (truly empty). The user must click Apply to push
   * the empty state to the URL.
   * Includes provider/account keys and all batch-managed filter keys.
   */
  clearAll: () => void;
  /**
   * Clear all batch-managed filters and immediately navigate (router.push)
   * with defaultParams applied. Equivalent to clearAll() + applyAll() but
   * avoids the async state gap between the two calls.
   */
  clearAndApply: () => void;
  /** Remove a single filter key from pending state */
  removePending: (key: string) => void;
  /** Whether pending state differs from the current URL */
  hasChanges: boolean;
  /** Number of filter keys that differ from the URL */
  changeCount: number;
  /** Get current value for a filter (pending if set, else from URL) */
  getFilterValue: (key: string) => string[];
}

/**
 * Derives the applied (URL-backed) filter state from `searchParams`.
 * Returns only the filter keys that are not excluded from batch management.
 */
function deriveAppliedFromUrl(searchParams: URLSearchParams): PendingFilters {
  const applied: PendingFilters = {};

  Array.from(searchParams.entries()).forEach(([key, value]) => {
    if (!key.startsWith("filter[")) return;
    if (EXCLUDED_FROM_BATCH.includes(key)) return;
    if (!value) return;

    applied[key] = value.split(",").filter(Boolean);
  });

  return applied;
}

/**
 * Compares two PendingFilters objects for shallow equality.
 * Two states are equal when they contain the same keys and the same sorted values.
 */
function areFiltersEqual(a: PendingFilters, b: PendingFilters): boolean {
  const keysA = Object.keys(a).filter((k) => a[k].length > 0);
  const keysB = Object.keys(b).filter((k) => b[k].length > 0);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) => {
    if (!b[key]) return false;
    const sortedA = [...a[key]].sort();
    const sortedB = [...b[key]].sort();
    if (sortedA.length !== sortedB.length) return false;
    return sortedA.every((v, i) => v === sortedB[i]);
  });
}

/**
 * Counts the number of filter keys that differ between pending and applied.
 */
function countChanges(
  pending: PendingFilters,
  applied: PendingFilters,
): number {
  const pendingKeys = Object.keys(pending).filter((k) => pending[k].length > 0);
  const appliedKeys = Object.keys(applied).filter((k) => applied[k].length > 0);

  // Merge all unique keys without Set iteration
  const allKeys = Array.from(new Set([...pendingKeys, ...appliedKeys]));

  let count = 0;
  allKeys.forEach((key) => {
    const p = pending[key] ?? [];
    const a = applied[key] ?? [];
    const sortedP = [...p].sort();
    const sortedA = [...a].sort();
    if (
      sortedP.length !== sortedA.length ||
      !sortedP.every((v, i) => v === sortedA[i])
    ) {
      count++;
    }
  });

  return count;
}

export interface UseFilterBatchOptions {
  /**
   * Default URL params to apply when applyAll() is called and they are not
   * already present in the params. Useful for page-level filter defaults
   * (e.g. `{ "filter[muted]": "false" }` on the Findings page).
   */
  defaultParams?: Record<string, string>;
}

/**
 * Manages a two-state (pending → applied) filter model for the Findings view.
 *
 * - Pending state lives only in this hook (React `useState`).
 * - Applied state is owned by the URL (`searchParams`).
 * - `applyAll()` performs a single `router.push()` with the full pending state.
 * - `discardAll()` resets pending to match the current URL.
 * - Browser back/forward automatically re-syncs pending state from the new URL.
 */
export const useFilterBatch = (
  options?: UseFilterBatchOptions,
): UseFilterBatchReturn => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [pendingFilters, setPendingFilters] = useState<PendingFilters>(() =>
    deriveAppliedFromUrl(new URLSearchParams(searchParams.toString())),
  );

  // Sync pending state whenever the URL changes (back/forward nav or external update).
  // `searchParams` from useSearchParams() is stable between renders in Next.js App Router.
  useEffect(() => {
    const applied = deriveAppliedFromUrl(
      new URLSearchParams(searchParams.toString()),
    );
    setPendingFilters(applied);
  }, [searchParams]);

  const setPending = (key: string, values: string[]) => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    setPendingFilters((prev) => ({
      ...prev,
      [filterKey]: values,
    }));
  };

  const removePending = (key: string) => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    setPendingFilters((prev) => {
      const next = { ...prev };
      delete next[filterKey];
      return next;
    });
  };

  /** Private helper — builds URLSearchParams from a pending state and pushes. */
  const buildAndPush = (nextPending: PendingFilters) => {
    const params = new URLSearchParams(searchParams.toString());

    // Remove all batch-managed filter params
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") && !EXCLUDED_FROM_BATCH.includes(key)) {
        params.delete(key);
      }
    });

    // Re-apply the given pending filters
    Object.entries(nextPending).forEach(([key, values]) => {
      const nonEmpty = values.filter(Boolean);
      if (nonEmpty.length > 0) {
        params.set(key, nonEmpty.join(","));
      }
    });

    // Apply caller-supplied defaults for any params not already set
    if (options?.defaultParams) {
      Object.entries(options.defaultParams).forEach(([key, value]) => {
        if (!params.has(key)) {
          params.set(key, value);
        }
      });
    }

    // Reset pagination
    if (params.has("page")) {
      params.set("page", "1");
    }

    const queryString = params.toString();
    const targetUrl = queryString ? `${pathname}?${queryString}` : pathname;
    router.push(targetUrl, { scroll: false });
  };

  const applyAll = () => {
    buildAndPush(pendingFilters);
  };

  const discardAll = () => {
    const applied = deriveAppliedFromUrl(
      new URLSearchParams(searchParams.toString()),
    );
    setPendingFilters(applied);
  };

  /**
   * Clears ALL pending batch filters to an empty state (no filters selected).
   *
   * Unlike `discardAll`, this resets pending to `{}` — not to the current URL
   * state. This covers both:
   * - Keys that are already in `pendingFilters` (pending-only or URL-loaded)
   * - Keys that are in the applied (URL) state but were removed from pending
   *   via `removePending` (edge case: diverged state)
   *
   * The user must click Apply to push the empty state to the URL.
   * `applyAll()` removes all batch-managed URL params first, so even keys
   * absent from `pendingFilters` will be removed from the URL on apply.
   */
  const clearAll = () => {
    // Return a truly empty object — no filters pending at all.
    // `getFilterValue` normalises missing keys to [] so selectors will show
    // their "all selected" / placeholder state immediately.
    setPendingFilters({});
  };

  /**
   * Clears ALL batch-managed filters and immediately navigates (router.push).
   *
   * Works around the async gap between clearAll() + applyAll(): instead of
   * setting pending to `{}` and then calling applyAll() (which would still
   * read the old pendingFilters from the closure), this function builds the
   * target URL directly from an empty pending state and pushes it in one step.
   * defaultParams (e.g. filter[muted]=false) are applied as usual.
   */
  const clearAndApply = () => {
    setPendingFilters({});
    buildAndPush({});
  };

  const getFilterValue = (key: string): string[] => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    return pendingFilters[filterKey] ?? [];
  };

  const appliedFilters = deriveAppliedFromUrl(
    new URLSearchParams(searchParams.toString()),
  );
  const hasChanges = !areFiltersEqual(pendingFilters, appliedFilters);
  const changeCount = hasChanges
    ? countChanges(pendingFilters, appliedFilters)
    : 0;

  return {
    pendingFilters,
    setPending,
    applyAll,
    discardAll,
    clearAll,
    clearAndApply,
    removePending,
    hasChanges,
    changeCount,
    getFilterValue,
  };
};
