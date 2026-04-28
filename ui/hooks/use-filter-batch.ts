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
  /** Current applied filter values — URL-backed state */
  appliedFilters: PendingFilters;
  /** Current pending filter values — local state, not yet in URL */
  pendingFilters: PendingFilters;
  /** Pending filter keys whose selected values differ from the applied URL state */
  changedFilters: PendingFilters;
  /** Update a single pending filter. Does NOT touch the URL. */
  setPending: (key: string, values: string[]) => void;
  /** Apply all pending filters to URL in a single router.push */
  applyAll: () => void;
  /** Discard all pending changes, reset pending to the current URL state */
  discardAll: () => void;
  /**
   * Clear all batch-managed filters and immediately navigate (router.push)
   * with defaultParams applied. Resets pending state to empty and pushes
   * the resulting URL in one step.
   */
  clearAndApply: () => void;
  /** Remove one applied URL-backed filter value and immediately navigate */
  removeAppliedAndApply: (key: string, value?: string) => void;
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

function getChangedFilters(
  pending: PendingFilters,
  applied: PendingFilters,
): PendingFilters {
  const pendingKeys = Object.keys(pending).filter((key) => {
    const values = pending[key];
    return values.length > 0;
  });
  const appliedKeys = Object.keys(applied).filter((key) => {
    const values = applied[key];
    return values.length > 0;
  });
  const allKeys = Array.from(new Set([...pendingKeys, ...appliedKeys]));

  return allKeys.reduce<PendingFilters>((changed, key) => {
    const pendingValues = pending[key] ?? [];
    const appliedValues = applied[key] ?? [];
    const sortedPending = [...pendingValues].sort();
    const sortedApplied = [...appliedValues].sort();
    const isChanged =
      sortedPending.length !== sortedApplied.length ||
      !sortedPending.every((value, index) => value === sortedApplied[index]);

    if (isChanged && pendingValues.length > 0) {
      changed[key] = pendingValues;
    }

    return changed;
  }, {});
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

  const [appliedFilters, setAppliedFilters] = useState<PendingFilters>(() =>
    deriveAppliedFromUrl(new URLSearchParams(searchParams.toString())),
  );
  const [pendingFilters, setPendingFilters] = useState<PendingFilters>(() =>
    deriveAppliedFromUrl(new URLSearchParams(searchParams.toString())),
  );

  // Sync pending state whenever the URL changes (back/forward nav or external update).
  // `searchParams` from useSearchParams() is stable between renders in Next.js App Router.
  useEffect(() => {
    const applied = deriveAppliedFromUrl(
      new URLSearchParams(searchParams.toString()),
    );
    setAppliedFilters(applied);
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
    setAppliedFilters(nextPending);
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
   * Clears ALL batch-managed filters and immediately navigates (router.push).
   *
   * Builds the target URL directly from an empty pending state and pushes it
   * in one step. defaultParams (e.g. filter[muted]=false) are applied as usual.
   */
  const clearAndApply = () => {
    setPendingFilters({});
    buildAndPush({});
  };

  const removeAppliedAndApply = (key: string, value?: string) => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    const applied = deriveAppliedFromUrl(
      new URLSearchParams(searchParams.toString()),
    );
    const nextValues =
      value === undefined
        ? []
        : (applied[filterKey] ?? []).filter((item) => item !== value);
    const nextApplied = { ...applied };

    if (nextValues.length > 0) {
      nextApplied[filterKey] = nextValues;
    } else {
      delete nextApplied[filterKey];
    }

    setPendingFilters(nextApplied);
    buildAndPush(nextApplied);
  };

  const getFilterValue = (key: string): string[] => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    return pendingFilters[filterKey] ?? [];
  };

  const hasChanges = !areFiltersEqual(pendingFilters, appliedFilters);
  const changeCount = hasChanges
    ? countChanges(pendingFilters, appliedFilters)
    : 0;
  const changedFilters = hasChanges
    ? getChangedFilters(pendingFilters, appliedFilters)
    : {};

  return {
    appliedFilters,
    pendingFilters,
    changedFilters,
    setPending,
    applyAll,
    discardAll,
    clearAndApply,
    removeAppliedAndApply,
    removePending,
    hasChanges,
    changeCount,
    getFilterValue,
  };
};
